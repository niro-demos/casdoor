// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"database/sql"
	"net/http/httptest"
	"strings"
	"testing"

	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// seedRawTestUser inserts a minimal row directly into the "user" table for
// (owner, name), bypassing object.AddUser (which requires a fully-wired
// organization + application and unrelated business rules) and
// object.DeleteUser (which unconditionally calls the package-level
// userEnforcer - nil unless object.InitUserManager() has run, which only
// happens from main.go, never from `go test`, and would panic on cleanup).
// The authorization gate under test (ApiController.IsAdmin / IsGlobalAdmin in
// controllers/base.go) only reads owner/name/is_admin off this table via
// object.GetUser, so a raw row is a faithful, minimal fixture for it.
// Registers cleanup that deletes the row via the same raw connection.
func seedRawTestUser(t *testing.T, owner, name string, isAdmin bool) {
	t.Helper()

	driverName := conf.GetConfigString("driverName")
	dsn := conf.GetConfigDataSourceName()
	if driverName == "mysql" {
		dsn += conf.GetConfigString("dbName")
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		t.Fatalf("failed to open a raw DB connection for test fixture setup: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach the test database at driver %q: %v", driverName, err)
	}

	// Clear any stale row from a previous failed run, then seed a fresh one.
	if _, err := db.Exec("DELETE FROM `user` WHERE owner = ? AND name = ?", owner, name); err != nil {
		t.Fatalf("failed to clear any stale test user row %s/%s: %v", owner, name, err)
	}

	_, err = db.Exec(
		"INSERT INTO `user` (owner, name, id, created_time, is_admin) VALUES (?, ?, ?, ?, ?)",
		owner, name, util.GenerateId(), util.GetCurrentTime(), isAdmin,
	)
	if err != nil {
		t.Fatalf("failed to seed test user %s/%s: %v", owner, name, err)
	}

	t.Cleanup(func() {
		if _, err := db.Exec("DELETE FROM `user` WHERE owner = ? AND name = ?", owner, name); err != nil {
			t.Logf("cleanup: failed to delete test user %s/%s: %v", owner, name, err)
		}
	})
}

// callRunCasbinCommand drives the real ApiController.RunCasbinCommand handler
// as `GET /api/run-casbin-command?language=go&args=["--version"]` would, with
// the session pinned to sessionUser (an "owner/name" user id, or "" for an
// unauthenticated caller). It bypasses the HTTP router/session store by
// writing straight to the same beego context field
// (Input.GetData("currentUserId")) that ApiController.GetSessionUsername
// reads first - the exact mechanism routers/authz_filter.go's real ApiFilter
// session middleware uses to attribute a request to a signed-in user
// (ctx.Input.SetData("currentUserId", username), including "" for anonymous).
func callRunCasbinCommand(t *testing.T, sessionUser string) *Response {
	t.Helper()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", `/api/run-casbin-command?language=go&args=["--version"]`, nil)
	ctx := beecontext.NewContext()
	ctx.Reset(w, r)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "RunCasbinCommand", nil)
	c.Ctx.Input.SetData("currentUserId", sessionUser)

	c.RunCasbinCommand()

	resp, ok := c.Data["json"].(*Response)
	if !ok {
		t.Fatalf("RunCasbinCommand as %q produced no JSON response: %+v", sessionUser, c.Data["json"])
	}
	return resp
}

// TestRunCasbinCommandRejectsOrgScopedAdmin is the regression test for
// TC-BE6F115E: controllers/casbin_cli_api.go RunCasbinCommand() gated on
// c.IsAdmin() (controllers/base.go - true for ANY user with IsAdmin=true,
// regardless of Owner) instead of c.IsGlobalAdmin() (true only for
// Owner=="built-in"). That let an org-scoped admin reach past the
// global-admin-only gate into the exec.LookPath()/exec.Command() CLI-exec
// logic meant to be reserved for the true instance/global admin.
//
// Invariant under test: an organization-scoped admin (Owner != "built-in")
// must be rejected with "Unauthorized operation" at the same gate an
// unauthenticated caller hits - it must never reach past that gate.
func TestRunCasbinCommandRejectsOrgScopedAdmin(t *testing.T) {
	object.InitConfig()

	const (
		testOrgName    = "NiroTCBE6F115EOrg"
		testAdminName  = "NiroTCBE6F115EOrgAdmin"
		testGlobalName = "NiroTCBE6F115EGlobalAdmin"
	)

	// Org-scoped admin: IsAdmin=true, Owner=testOrgName != "built-in" -
	// mirrors the finding's ACME_ORG_ADMIN fixture (a non-global admin whose
	// Owner is their own organization, not "built-in").
	seedRawTestUser(t, testOrgName, testAdminName, true)
	// True global admin control: Owner == "built-in".
	seedRawTestUser(t, "built-in", testGlobalName, true)

	// --- Positive control: an unauthenticated caller must be rejected at the
	// gate, exactly like the PoC's own control. If this ever stops failing
	// the way it should, the harness itself is broken, not the invariant.
	anon := callRunCasbinCommand(t, "")
	if anon.Status != "error" || !strings.Contains(anon.Msg, "Unauthorized operation") {
		t.Fatalf("baseline broken: unauthenticated caller was not rejected the expected way: status=%q msg=%q", anon.Status, anon.Msg)
	}

	// --- Exploit (the RED check): an org-scoped admin (Owner=testOrgName,
	// IsAdmin=true, NOT Owner=="built-in") must be rejected the same way -
	// never reaching the CLI-exec logic past the gate.
	orgAdminResp := callRunCasbinCommand(t, util.GetId(testOrgName, testAdminName))
	if orgAdminResp.Status != "error" || !strings.Contains(orgAdminResp.Msg, "Unauthorized operation") {
		t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin %s/%s (Owner != \"built-in\") was not rejected at the global-admin gate - it reached past IsAdmin() into the CLI-exec logic: status=%q msg=%q",
			testOrgName, testAdminName, orgAdminResp.Status, orgAdminResp.Msg)
	}

	// --- Control (must stay green): the SAME endpoint, requested by a TRUE
	// global admin (Owner == "built-in"), must NOT be rejected at this gate -
	// proving the fix confines the endpoint to org-scoped admins specifically,
	// not that it now rejects everyone.
	globalAdminResp := callRunCasbinCommand(t, util.GetId("built-in", testGlobalName))
	if globalAdminResp.Status == "error" && strings.Contains(globalAdminResp.Msg, "Unauthorized operation") {
		t.Fatalf("control broken: the true global admin (built-in/%s) was rejected at the global-admin gate too - the fix over-restricted the endpoint", testGlobalName)
	}
}
