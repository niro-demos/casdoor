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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// casbinApiTestSetup boots just enough of the app (config + DB connection +
// an in-memory session manager) for ApiController methods to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used by object package tests (see object/user_test.go, which calls
// object.InitConfig() directly against a real database).
var casbinApiTestSetup sync.Once

func initCasbinApiTest(t *testing.T) {
	t.Helper()

	casbinApiTestSetup.Do(func() {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			panic("failed to resolve test file path")
		}
		repoRoot := filepath.Dir(filepath.Dir(thisFile))

		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id_test"
		web.BConfig.WebConfig.Session.SessionGCMaxLifetime = 3600

		// Loads conf/app.conf (real MySQL DSN) and registers beego's session
		// manager, mirroring what main.go does at startup.
		web.TestBeegoInit(repoRoot)

		object.InitAdapter()
		object.CreateTables()
		object.InitDb()
		object.InitUserManager()
	})
}

// callCasbinGetAll simulates a GET to /api/get-all-<endpoint>[?userId=...]
// with the given (possibly empty, meaning unauthenticated) session username,
// by driving the ApiController method directly -- the same seam the
// vulnerability lived in.
func callCasbinGetAll(t *testing.T, endpoint, sessionUsername, userIdParam string) *Response {
	t.Helper()

	target := "/api/get-all-" + endpoint
	if userIdParam != "" {
		target += "?userId=" + url.QueryEscape(userIdParam)
	}

	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(w, req)

	sess, err := web.GlobalSessions.SessionStart(w, req)
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	defer sess.SessionRelease(context.Background(), w)
	ctx.Input.CruSession = sess

	if sessionUsername != "" {
		if err := sess.Set(context.Background(), "username", sessionUsername); err != nil {
			t.Fatalf("failed to set session username: %v", err)
		}
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetAll", nil)

	switch endpoint {
	case "roles":
		c.GetAllRoles()
	case "objects":
		c.GetAllObjects()
	case "actions":
		c.GetAllActions()
	default:
		t.Fatalf("unknown endpoint %q", endpoint)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), err)
	}
	return &resp
}

func responseContainsString(resp *Response, needle string) bool {
	arr, ok := resp.Data.([]interface{})
	if !ok {
		return false
	}
	for _, v := range arr {
		if s, ok := v.(string); ok && s == needle {
			return true
		}
	}
	return false
}

// setupCasbinApiOrg creates an organization plus one application for it (an
// application is required before any user can be added to a non-built-in
// organization), and registers cleanup.
func setupCasbinApiOrg(t *testing.T, orgName string) {
	t.Helper()

	org := &object.Organization{
		Owner:       "admin",
		Name:        orgName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: orgName,
	}
	ok, err := object.AddOrganization(org)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture organization %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(org) })

	app := &object.Application{
		Owner:        "admin",
		Name:         "app-" + orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "app-" + orgName,
		Organization: orgName,
	}
	ok, err = object.AddApplication(app)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture application for %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })
}

// setupCasbinApiUser creates a user in orgName and registers cleanup.
func setupCasbinApiUser(t *testing.T, orgName, name string, isAdmin bool) *object.User {
	t.Helper()

	user := &object.User{
		Owner:       orgName,
		Name:        name,
		Id:          orgName + "/" + name,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: name,
		IsAdmin:     isAdmin,
	}
	ok, err := object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s/%s: ok=%v err=%v", orgName, name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// TestGetAllRolesObjectsActionsRejectForeignUserId is the regression test for
// TC-F1155ABE: an unauthenticated caller, an unrelated same-org user, and a
// cross-tenant user must not be able to read another user's roles, objects,
// or actions by supplying that user's id in the `userId` query parameter.
// The invariant under test: only the user themselves, or an admin with
// authority over the target user's organization, may look up that user's
// bindings.
func TestGetAllRolesObjectsActionsRejectForeignUserId(t *testing.T) {
	initCasbinApiTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgAlpha := "casbin-it-alpha-" + suffix
	orgBeta := "casbin-it-beta-" + suffix
	roleName := "role-test-" + suffix
	permName := "perm-test-" + suffix
	resourceName := "secret-resource-" + suffix

	setupCasbinApiOrg(t, orgAlpha)
	setupCasbinApiOrg(t, orgBeta)

	alice := setupCasbinApiUser(t, orgAlpha, "alice", false)
	bob := setupCasbinApiUser(t, orgAlpha, "bob", false)
	admin := setupCasbinApiUser(t, orgAlpha, "admin", true)
	eve := setupCasbinApiUser(t, orgBeta, "eve", false)

	role := &object.Role{
		Owner:       orgAlpha,
		Name:        roleName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: roleName,
		Users:       []string{alice.GetId()},
		IsEnabled:   true,
	}
	ok, err := object.AddRole(role)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture role: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteRole(role) })

	permission := &object.Permission{
		Owner:       orgAlpha,
		Name:        permName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: permName,
		Roles:       []string{role.GetId()},
		Resources:   []string{resourceName},
		Actions:     []string{"Read", "Write"},
		Effect:      "Allow",
		IsEnabled:   true,
	}
	ok, err = object.AddPermission(permission)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture permission: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeletePermission(permission) })

	aliceId := alice.GetId()

	checks := []struct {
		endpoint string
		needle   string
	}{
		{"roles", roleName},
		{"objects", resourceName},
		{"actions", "Write"},
	}

	for _, chk := range checks {
		chk := chk

		t.Run(chk.endpoint+"/anonymous_caller_denied", func(t *testing.T) {
			resp := callCasbinGetAll(t, chk.endpoint, "", aliceId)
			if resp.Status == "ok" && responseContainsString(resp, chk.needle) {
				t.Fatalf("unauthenticated caller retrieved alice's %s via userId param: %+v", chk.endpoint, resp)
			}
		})

		t.Run(chk.endpoint+"/unrelated_same_org_caller_denied", func(t *testing.T) {
			resp := callCasbinGetAll(t, chk.endpoint, bob.GetId(), aliceId)
			if resp.Status == "ok" && responseContainsString(resp, chk.needle) {
				t.Fatalf("unrelated same-org caller (bob) retrieved alice's %s via userId param: %+v", chk.endpoint, resp)
			}
		})

		t.Run(chk.endpoint+"/cross_tenant_caller_denied", func(t *testing.T) {
			resp := callCasbinGetAll(t, chk.endpoint, eve.GetId(), aliceId)
			if resp.Status == "ok" && responseContainsString(resp, chk.needle) {
				t.Fatalf("cross-tenant caller (eve) retrieved alice's %s via userId param: %+v", chk.endpoint, resp)
			}
		})

		// Positive controls: legitimate callers must keep working, proving
		// the denials above are the missing ownership check, not a broken
		// environment or an overly strict fix.
		t.Run(chk.endpoint+"/self_via_own_session_allowed", func(t *testing.T) {
			resp := callCasbinGetAll(t, chk.endpoint, aliceId, "")
			if resp.Status != "ok" || !responseContainsString(resp, chk.needle) {
				t.Fatalf("control failed: alice could not read her own %s via her own session: %+v", chk.endpoint, resp)
			}
		})

		t.Run(chk.endpoint+"/self_via_explicit_userId_allowed", func(t *testing.T) {
			resp := callCasbinGetAll(t, chk.endpoint, aliceId, aliceId)
			if resp.Status != "ok" || !responseContainsString(resp, chk.needle) {
				t.Fatalf("control failed: alice could not read her own %s via explicit userId: %+v", chk.endpoint, resp)
			}
		})

		t.Run(chk.endpoint+"/org_admin_allowed", func(t *testing.T) {
			resp := callCasbinGetAll(t, chk.endpoint, admin.GetId(), aliceId)
			if resp.Status != "ok" || !responseContainsString(resp, chk.needle) {
				t.Fatalf("control failed: alice's org admin could not read her %s via userId: %+v", chk.endpoint, resp)
			}
		})
	}
}
