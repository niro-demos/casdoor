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

// Regression tests for a class of authorization bugs where a platform-global
// operation was gated with IsAdmin()/RequireAdmin() - true for *any*
// organization's tenant-scoped admin - instead of IsGlobalAdmin(), which is
// true only for the platform's built-in global administrator. Each handler
// below executes a shared, server-wide, non-tenant-scoped capability
// (running an OS binary, downloading/installing shared CLI engines, reading
// platform-wide telemetry), so a tenant admin of any organization must not
// be able to reach it - only the built-in global admin may.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	_ "github.com/go-sql-driver/mysql"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
)

// gateTestFixture holds the ids (owner/name) of three fixture users seeded
// directly into the users table for these tests:
//   - the platform's built-in global administrator (Owner == "built-in")
//   - a tenant-scoped organization admin (IsAdmin == true, Owner != "built-in")
//   - a non-admin standard user, used only as a negative control
//
// Fixtures are inserted with plain SQL rather than object.AddUser because
// AddUser drives the full signup validation path (organization must exist,
// must own at least one application, "built-in" org consent flag, password
// hashing, ...) which is unrelated to what these tests exercise: the
// authorization decision a handler makes once a user id is already resolved
// into the request context - exactly how routers/authz_filter.go's
// ApiFilter hands control to a controller in production, via
// ctx.Input.SetData("currentUserId", ...).
type gateTestFixture struct {
	GlobalAdminId string
	OrgAdminId    string
	StandardId    string
}

func newGateTestFixture(t *testing.T) *gateTestFixture {
	t.Helper()

	object.InitConfig()

	dsn := conf.GetConfigDataSourceName() + conf.GetConfigString("dbName")
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("failed to open test DB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	suffix := time.Now().UnixNano()
	org := fmt.Sprintf("niro-fix-gate-org-%d", suffix)
	globalAdminName := fmt.Sprintf("niro-fix-gate-global-admin-%d", suffix)

	type fixtureRow struct {
		owner, name string
		isAdmin     bool
	}
	rows := []fixtureRow{
		{"built-in", globalAdminName, false},
		{org, "admin", true},
		{org, "alice", false},
	}

	for _, r := range rows {
		if _, err := db.Exec(
			"INSERT INTO user (owner, name, is_admin, created_time) VALUES (?, ?, ?, ?)",
			r.owner, r.name, r.isAdmin, time.Now().Format(time.RFC3339),
		); err != nil {
			t.Fatalf("failed to seed fixture user %s/%s: %v", r.owner, r.name, err)
		}
	}
	t.Cleanup(func() {
		for _, r := range rows {
			if _, err := db.Exec("DELETE FROM user WHERE owner = ? AND name = ?", r.owner, r.name); err != nil {
				t.Logf("failed to clean up fixture user %s/%s: %v", r.owner, r.name, err)
			}
		}
	})

	return &gateTestFixture{
		GlobalAdminId: "built-in/" + globalAdminName,
		OrgAdminId:    org + "/admin",
		StandardId:    org + "/alice",
	}
}

// newGateTestController builds a minimal ApiController wired to a real
// beego context and an httptest recorder, with the session pre-seeded to
// the given user id the same way ApiFilter seeds "currentUserId" for a real
// authenticated request. userId == "" simulates an unauthenticated caller.
func newGateTestController(method, path, userId string) (*ApiController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "", nil)

	if userId != "" {
		ctx.Input.SetData("currentUserId", userId)
	}

	return c, w
}

func gateTestStatusAndMsg(t *testing.T, w *httptest.ResponseRecorder) (status, msg string) {
	t.Helper()
	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response %q: %v", w.Body.String(), err)
	}
	return resp.Status, resp.Msg
}

// TestRunCasbinCommandRequiresGlobalAdmin asserts the invariant for
// TC-82082C5B: only the platform's global administrator may reach
// RunCasbinCommand, which executes an OS binary with caller-supplied
// arguments on the shared server.
func TestRunCasbinCommandRequiresGlobalAdmin(t *testing.T) {
	fx := newGateTestFixture(t)
	const path = "/api/run-casbin-command?language=go&args=%5B%22--version%22%5D"

	// Control: the true global admin must still reach past the
	// authorization gate. No valid m/t identifier is supplied, so the call
	// still fails - at identifier validation, not at the auth gate - which
	// is how we know it passed authorization.
	c, w := newGateTestController("GET", path, fx.GlobalAdminId)
	c.RunCasbinCommand()
	if status, msg := gateTestStatusAndMsg(t, w); status != "error" || msg != "invalid identifier" {
		t.Fatalf("global admin: got status=%q msg=%q, want to pass the auth gate (invalid identifier)", status, msg)
	}

	// Invariant: a tenant-scoped organization admin (IsAdmin==true, not the
	// global admin) must be rejected at the authorization gate itself.
	c, w = newGateTestController("GET", path, fx.OrgAdminId)
	c.RunCasbinCommand()
	if status, msg := gateTestStatusAndMsg(t, w); status != "error" || msg != "Unauthorized operation" {
		t.Fatalf("org admin: got status=%q msg=%q, want Unauthorized operation (must not reach the CLI runner)", status, msg)
	}

	// Negative control: a non-admin user was already correctly blocked.
	c, w = newGateTestController("GET", path, fx.StandardId)
	c.RunCasbinCommand()
	if status, msg := gateTestStatusAndMsg(t, w); status != "error" || msg != "Unauthorized operation" {
		t.Fatalf("standard user: got status=%q msg=%q, want Unauthorized operation", status, msg)
	}
}

// TestRefreshEnginesRequiresGlobalAdmin asserts the invariant for
// TC-393405A8: only the platform's global administrator may trigger a
// server-wide download/install of the shared Casbin CLI engine binaries.
func TestRefreshEnginesRequiresGlobalAdmin(t *testing.T) {
	fx := newGateTestFixture(t)
	const path = "/api/refresh-engines"

	// Control: the true global admin still passes the authorization gate.
	// No m/t identifier is supplied, so the call still fails past the gate.
	c, w := newGateTestController("POST", path, fx.GlobalAdminId)
	c.RefreshEngines()
	if status, msg := gateTestStatusAndMsg(t, w); status != "error" || msg != "invalid identifier" {
		t.Fatalf("global admin: got status=%q msg=%q, want to pass the auth gate (invalid identifier)", status, msg)
	}

	// Invariant: a tenant-scoped organization admin must be rejected at the
	// authorization gate.
	c, w = newGateTestController("POST", path, fx.OrgAdminId)
	c.RefreshEngines()
	if status, msg := gateTestStatusAndMsg(t, w); status != "error" || msg != "Unauthorized operation" {
		t.Fatalf("org admin: got status=%q msg=%q, want Unauthorized operation (must not trigger a server-wide engine refresh)", status, msg)
	}

	// Negative control.
	c, w = newGateTestController("POST", path, fx.StandardId)
	c.RefreshEngines()
	if status, msg := gateTestStatusAndMsg(t, w); status != "error" || msg != "Unauthorized operation" {
		t.Fatalf("standard user: got status=%q msg=%q, want Unauthorized operation", status, msg)
	}
}

// TestGetPrometheusInfoRequiresGlobalAdmin asserts the invariant for
// TC-02A080A3: platform-wide Prometheus telemetry (raw request paths and
// embedded resource identifiers for every tenant) must be restricted to the
// platform's global administrator.
func TestGetPrometheusInfoRequiresGlobalAdmin(t *testing.T) {
	fx := newGateTestFixture(t)
	const path = "/api/get-prometheus-info"

	// Control: the true global admin must still be able to read the data.
	c, w := newGateTestController("GET", path, fx.GlobalAdminId)
	c.GetPrometheusInfo()
	if status, _ := gateTestStatusAndMsg(t, w); status != "ok" {
		t.Fatalf("global admin: got status=%q, want ok (must retain access to platform metrics)", status)
	}

	// Invariant: a tenant-scoped organization admin must not be able to
	// read platform-wide metrics.
	c, w = newGateTestController("GET", path, fx.OrgAdminId)
	c.GetPrometheusInfo()
	if status, msg := gateTestStatusAndMsg(t, w); status != "error" || msg != "this operation requires administrator to perform" {
		t.Fatalf("org admin: got status=%q msg=%q, want the administrator-required error (must not read cross-tenant metrics)", status, msg)
	}

	// Negative control: a non-admin user was already correctly blocked.
	c, w = newGateTestController("GET", path, fx.StandardId)
	c.GetPrometheusInfo()
	if status, msg := gateTestStatusAndMsg(t, w); status != "error" || msg != "this operation requires administrator to perform" {
		t.Fatalf("standard user: got status=%q msg=%q, want the administrator-required error", status, msg)
	}
}
