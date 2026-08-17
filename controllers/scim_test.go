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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// scimApiTestSetup boots just enough of the app (config + DB connection + an
// in-memory session manager) for RootController.HandleScim to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used by object package tests (see object/user_test.go, which calls
// object.InitConfig() directly against a real database).
var scimApiTestSetup sync.Once

func initScimApiTest(t *testing.T) {
	t.Helper()

	scimApiTestSetup.Do(func() {
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

// scimResponse is the decoded result of driving RootController.HandleScim
// directly.
type scimResponse struct {
	status int
	body   map[string]interface{}
	raw    []byte
}

// callScim simulates an HTTP request to /scim/... with the given (possibly
// empty, meaning unauthenticated) session username, by driving
// RootController.HandleScim directly -- the same seam the vulnerability lived
// in (controllers/scim.go discarding the organization RequireAdmin()
// returns).
func callScim(t *testing.T, method, target, sessionUsername, body, contentType string) *scimResponse {
	t.Helper()

	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, reader)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
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

	c := &RootController{}
	c.Init(ctx, "RootController", "HandleScim", nil)
	c.HandleScim()

	raw := w.Body.Bytes()
	resp := &scimResponse{status: w.Code, raw: raw}
	_ = json.Unmarshal(raw, &resp.body) // best-effort; SCIM errors and objects both decode to a map
	return resp
}

// setupScimOrg creates an organization plus one application for it (an
// application is required before any user can be added to a non-built-in
// organization), and registers cleanup.
func setupScimOrg(t *testing.T, orgName string) {
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

// setupScimUser creates a user in orgName (with a globally unique SCIM Id)
// and registers cleanup.
func setupScimUser(t *testing.T, orgName, name string, isAdmin bool) *object.User {
	t.Helper()

	user := &object.User{
		Owner:       orgName,
		Name:        name,
		Id:          orgName + "-" + name,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Display " + name,
		Email:       fmt.Sprintf("%s-%s@example.com", orgName, name),
		IsAdmin:     isAdmin,
	}
	ok, err := object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s/%s: ok=%v err=%v", orgName, name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// builtInAdmin returns the seeded "built-in/admin" superadmin (created by
// object.InitDb() at app boot). RequireAdmin() treats Owner=="built-in" as
// the unscoped global admin, and object.AddUser refuses to create additional
// "built-in" org users outside of "admin" unless the organization's "Has
// privilege consent" flag is set -- so tests read-only-use the one seeded
// global admin instead of minting their own.
func builtInAdmin(t *testing.T) *object.User {
	t.Helper()

	user, err := object.GetUser("built-in/admin")
	if err != nil {
		t.Fatalf("failed to look up seeded built-in admin: %v", err)
	}
	if user == nil {
		t.Fatal("seeded built-in/admin user not found -- object.InitDb() should have created it")
	}
	return user
}

// setupScimGroup creates a group in orgName and registers cleanup.
func setupScimGroup(t *testing.T, orgName, name string) *object.Group {
	t.Helper()

	group := &object.Group{
		Owner:       orgName,
		Name:        name,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Display " + name,
		IsTopGroup:  true,
		IsEnabled:   true,
	}
	ok, err := object.AddGroup(group)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture group %s/%s: ok=%v err=%v", orgName, name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteGroup(group) })

	return group
}

// TestScimUserRejectsCrossOrganizationAccess is the regression test for
// TC-F618CE0E: a tenant admin of one organization (alpha) must not be able to
// read, enumerate, or mutate a user record belonging to a different
// organization (beta) through the SCIM provisioning API. The invariant under
// test: SCIM /Users is confined to the caller's own organization unless the
// caller is the built-in global admin.
func TestScimUserRejectsCrossOrganizationAccess(t *testing.T) {
	initScimApiTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgAlpha := "scim-it-alpha-" + suffix
	orgBeta := "scim-it-beta-" + suffix

	setupScimOrg(t, orgAlpha)
	setupScimOrg(t, orgBeta)

	alphaAdmin := setupScimUser(t, orgAlpha, "admin", true)
	betaAdmin := setupScimUser(t, orgBeta, "admin", true)
	betaAlice := setupScimUser(t, orgBeta, "alice", false)

	scimPath := "/scim/Users/" + betaAlice.Id

	t.Run("cross_tenant_get_denied", func(t *testing.T) {
		resp := callScim(t, http.MethodGet, scimPath, alphaAdmin.GetId(), "", "")
		if resp.status == http.StatusOK {
			t.Fatalf("alpha admin read a beta user via SCIM GET: status=%d body=%s", resp.status, resp.raw)
		}
	})

	t.Run("cross_tenant_patch_denied", func(t *testing.T) {
		patchBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"PWNED-by-alpha-admin"}]}`
		resp := callScim(t, http.MethodPatch, scimPath, alphaAdmin.GetId(), patchBody, "application/scim+json")
		if resp.status == http.StatusOK {
			t.Fatalf("alpha admin patched a beta user via SCIM PATCH: status=%d body=%s", resp.status, resp.raw)
		}

		// Whatever HandleScim answered, the record itself must be unchanged
		// when re-read by its true owner.
		verify := callScim(t, http.MethodGet, scimPath, betaAdmin.GetId(), "", "")
		if verify.status != http.StatusOK {
			t.Fatalf("beta admin could not re-read its own user after the cross-tenant PATCH attempt: status=%d body=%s", verify.status, verify.raw)
		}
		if verify.body["displayName"] == "PWNED-by-alpha-admin" {
			t.Fatalf("beta user's displayName was mutated by the alpha admin's cross-tenant PATCH: %+v", verify.body)
		}
	})

	t.Run("cross_tenant_list_excludes_foreign_org", func(t *testing.T) {
		resp := callScim(t, http.MethodGet, "/scim/Users?count=100", alphaAdmin.GetId(), "", "")
		if resp.status != http.StatusOK {
			t.Fatalf("alpha admin could not list SCIM users at all: status=%d body=%s", resp.status, resp.raw)
		}
		resources, _ := resp.body["Resources"].([]interface{})
		for _, res := range resources {
			m, ok := res.(map[string]interface{})
			if !ok {
				continue
			}
			if m["id"] == betaAlice.Id {
				t.Fatalf("alpha admin's SCIM Users list included the beta user %q: %+v", betaAlice.Id, resp.body)
			}
		}
	})

	// Positive control: the true owner's own admin can read the user via
	// SCIM. If this fails, the denials above would be meaningless -- they'd
	// just reflect a broken environment, not the invariant.
	t.Run("same_tenant_get_allowed", func(t *testing.T) {
		resp := callScim(t, http.MethodGet, scimPath, betaAdmin.GetId(), "", "")
		if resp.status != http.StatusOK || resp.body["id"] != betaAlice.Id {
			t.Fatalf("control failed: beta admin (true owner) could not read its own user via SCIM: status=%d body=%s", resp.status, resp.raw)
		}
	})

	// Positive control: the fix must not regress the built-in global admin,
	// who is legitimately meant to reach every organization's users.
	t.Run("global_admin_get_allowed", func(t *testing.T) {
		globalAdmin := builtInAdmin(t)
		resp := callScim(t, http.MethodGet, scimPath, globalAdmin.GetId(), "", "")
		if resp.status != http.StatusOK || resp.body["id"] != betaAlice.Id {
			t.Fatalf("control failed: built-in global admin could not read a beta user via SCIM: status=%d body=%s", resp.status, resp.raw)
		}
	})
}

// TestScimGroupRejectsCrossOrganizationAccess mirrors
// TestScimUserRejectsCrossOrganizationAccess for the Groups resource, which
// diagnosis.md identifies as having the identical missing-tenant-scope
// pattern as Users.
func TestScimGroupRejectsCrossOrganizationAccess(t *testing.T) {
	initScimApiTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgAlpha := "scim-it-galpha-" + suffix
	orgBeta := "scim-it-gbeta-" + suffix

	setupScimOrg(t, orgAlpha)
	setupScimOrg(t, orgBeta)

	alphaAdmin := setupScimUser(t, orgAlpha, "admin", true)
	betaAdmin := setupScimUser(t, orgBeta, "admin", true)
	betaGroup := setupScimGroup(t, orgBeta, "engineering")

	scimPath := "/scim/Groups/" + betaGroup.GetId()

	t.Run("cross_tenant_get_denied", func(t *testing.T) {
		resp := callScim(t, http.MethodGet, scimPath, alphaAdmin.GetId(), "", "")
		if resp.status == http.StatusOK {
			t.Fatalf("alpha admin read a beta group via SCIM GET: status=%d body=%s", resp.status, resp.raw)
		}
	})

	t.Run("cross_tenant_patch_denied", func(t *testing.T) {
		patchBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"PWNED-group-by-alpha-admin"}]}`
		resp := callScim(t, http.MethodPatch, scimPath, alphaAdmin.GetId(), patchBody, "application/scim+json")
		if resp.status == http.StatusOK {
			t.Fatalf("alpha admin patched a beta group via SCIM PATCH: status=%d body=%s", resp.status, resp.raw)
		}

		verify := callScim(t, http.MethodGet, scimPath, betaAdmin.GetId(), "", "")
		if verify.status != http.StatusOK {
			t.Fatalf("beta admin could not re-read its own group after the cross-tenant PATCH attempt: status=%d body=%s", verify.status, verify.raw)
		}
		if verify.body["displayName"] == "PWNED-group-by-alpha-admin" {
			t.Fatalf("beta group's displayName was mutated by the alpha admin's cross-tenant PATCH: %+v", verify.body)
		}
	})

	t.Run("cross_tenant_list_excludes_foreign_org", func(t *testing.T) {
		resp := callScim(t, http.MethodGet, "/scim/Groups?count=100", alphaAdmin.GetId(), "", "")
		if resp.status != http.StatusOK {
			t.Fatalf("alpha admin could not list SCIM groups at all: status=%d body=%s", resp.status, resp.raw)
		}
		resources, _ := resp.body["Resources"].([]interface{})
		for _, res := range resources {
			m, ok := res.(map[string]interface{})
			if !ok {
				continue
			}
			if m["id"] == betaGroup.GetId() {
				t.Fatalf("alpha admin's SCIM Groups list included the beta group %q: %+v", betaGroup.GetId(), resp.body)
			}
		}
	})

	// Positive control.
	t.Run("same_tenant_get_allowed", func(t *testing.T) {
		resp := callScim(t, http.MethodGet, scimPath, betaAdmin.GetId(), "", "")
		if resp.status != http.StatusOK || resp.body["id"] != betaGroup.GetId() {
			t.Fatalf("control failed: beta admin (true owner) could not read its own group via SCIM: status=%d body=%s", resp.status, resp.raw)
		}
	})

	// Positive control: the fix must not regress the built-in global admin,
	// who is legitimately meant to reach every organization's groups.
	t.Run("global_admin_get_allowed", func(t *testing.T) {
		globalAdmin := builtInAdmin(t)
		resp := callScim(t, http.MethodGet, scimPath, globalAdmin.GetId(), "", "")
		if resp.status != http.StatusOK || resp.body["id"] != betaGroup.GetId() {
			t.Fatalf("control failed: built-in global admin could not read a beta group via SCIM: status=%d body=%s", resp.status, resp.raw)
		}
	})
}
