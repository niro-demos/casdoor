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
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var initAuthzScopeTestDbOnce sync.Once

// initAuthzScopeTestDb wires up the same DB the running app uses
// (conf/app.conf), mirroring object.TestDumpToFile's setup convention.
func initAuthzScopeTestDb(t *testing.T) {
	t.Helper()
	initAuthzScopeTestDbOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
		object.InitUserManager()
	})
}

// newTestApiController builds an ApiController wired to a fake request whose
// query string is rawQuery, with currentUserId and objOwner stashed exactly
// as routers.ApiFilter would stash them for a real request (see
// ApiFilter in routers/authz_filter.go): currentUserId is read by
// GetSessionUsername(), objOwner by getRequestObjOwner().
func newTestApiController(currentUserId, objOwner, rawQuery string) *ApiController {
	c, _ := newTestApiControllerWithRecorder(currentUserId, objOwner, rawQuery)
	return c
}

// newTestApiControllerWithRecorder is like newTestApiController but also
// returns the underlying response recorder, for tests that need to inspect
// the JSON a handler wrote via c.ServeJSON()/c.ResponseOk().
func newTestApiControllerWithRecorder(currentUserId, objOwner, rawQuery string) (*ApiController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest("GET", "/api/test?"+rawQuery, nil)
	rec := httptest.NewRecorder()

	ctx := context.NewContext()
	ctx.Reset(rec, req)
	ctx.Input.SetData("currentUserId", currentUserId)
	ctx.Input.SetData("objOwner", objOwner)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "Test", nil)
	return c, rec
}

// TestIsGlobalAdminScopesAppToOwnOrganization reproduces the TC-A2059D90
// trust assumption in isGlobalAdmin(): an app-authenticated identity (session
// username of the form "app/<name>", see routers.getUsernameByClientIdSecret)
// must only be treated as an admin for requests targeting its own
// organization, not as a platform-wide global admin over every tenant (which
// is what GetTickets's c.IsAdmin() call relies on for TC-A2059D90's
// /api/get-tickets PoC).
func TestIsGlobalAdminScopesAppToOwnOrganization(t *testing.T) {
	initAuthzScopeTestDb(t)

	suffix := util.GenerateId()[:8]
	orgAlphaName := "ctrl-test-org-alpha-" + suffix
	orgBetaName := "ctrl-test-org-beta-" + suffix
	appName := "ctrl-test-app-alpha-" + suffix

	orgAlpha := &object.Organization{Owner: "admin", Name: orgAlphaName, DisplayName: "Alpha"}
	if ok, err := object.AddOrganization(orgAlpha); err != nil || !ok {
		t.Fatalf("failed to seed org alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(orgAlpha) })

	app := &object.Application{Owner: "admin", Name: appName, Organization: orgAlphaName, DisplayName: "Alpha App"}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("failed to seed application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	appIdentity := util.GetId("app", appName)

	// THE VIOLATION: app-alpha's own client credentials, on a request
	// targeting org beta, must not be treated as a global admin.
	c := newTestApiController(appIdentity, orgBetaName, "owner="+orgBetaName)
	if c.IsAdmin() {
		t.Fatalf("invariant violated: app %q (organization %q) was treated as a global admin for a request targeting organization %q", appName, orgAlphaName, orgBetaName)
	}

	// GREEN CONTROL: the same app credentials must still be trusted for a
	// request targeting its own organization.
	c = newTestApiController(appIdentity, orgAlphaName, "owner="+orgAlphaName)
	if !c.IsAdmin() {
		t.Fatalf("regression: app %q's own client credentials were denied admin trust for its own organization %q", appName, orgAlphaName)
	}
}

// TestIsOrgAdminScopesAppToOwnOrganization reproduces the same trust
// assumption in IsOrgAdmin(), the sole gate on GetResources
// (controllers/resource.go): an app identity must only be treated as an org
// admin for its own organization.
func TestIsOrgAdminScopesAppToOwnOrganization(t *testing.T) {
	initAuthzScopeTestDb(t)

	suffix := util.GenerateId()[:8]
	orgAlphaName := "ctrl-test-org-alpha-" + suffix
	orgBetaName := "ctrl-test-org-beta-" + suffix
	appName := "ctrl-test-app-alpha-" + suffix

	orgAlpha := &object.Organization{Owner: "admin", Name: orgAlphaName, DisplayName: "Alpha"}
	if ok, err := object.AddOrganization(orgAlpha); err != nil || !ok {
		t.Fatalf("failed to seed org alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(orgAlpha) })

	app := &object.Application{Owner: "admin", Name: appName, Organization: orgAlphaName, DisplayName: "Alpha App"}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("failed to seed application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	appIdentity := util.GetId("app", appName)

	// THE VIOLATION: app-alpha's own client credentials, on a request
	// targeting org beta's resources, must not be treated as org beta's
	// admin.
	c := newTestApiController(appIdentity, orgBetaName, "owner="+orgBetaName)
	isOrgAdmin, ok := c.IsOrgAdmin()
	if !ok {
		t.Fatalf("IsOrgAdmin unexpectedly failed the request")
	}
	if isOrgAdmin {
		t.Fatalf("invariant violated: app %q (organization %q) was treated as org-admin for organization %q's resources", appName, orgAlphaName, orgBetaName)
	}

	// GREEN CONTROL: same app credentials, own organization.
	c = newTestApiController(appIdentity, orgAlphaName, "owner="+orgAlphaName)
	isOrgAdmin, ok = c.IsOrgAdmin()
	if !ok {
		t.Fatalf("IsOrgAdmin unexpectedly failed the request")
	}
	if !isOrgAdmin {
		t.Fatalf("regression: app %q's own client credentials were denied org-admin trust for its own organization %q", appName, orgAlphaName)
	}
}

// TestRequireSignedInUserScopesAppImpersonationToOwnOrganization reproduces
// the TC-A2059D90 trust assumption in RequireSignedInUser(): an
// app-authenticated identity must not be able to act as an arbitrary user
// from any tenant by supplying a "userId" query parameter -- only as a user
// within its own application's organization.
func TestRequireSignedInUserScopesAppImpersonationToOwnOrganization(t *testing.T) {
	initAuthzScopeTestDb(t)

	suffix := util.GenerateId()[:8]
	orgAlphaName := "ctrl-test-org-alpha-" + suffix
	orgBetaName := "ctrl-test-org-beta-" + suffix
	appName := "ctrl-test-app-alpha-" + suffix

	orgAlpha := &object.Organization{Owner: "admin", Name: orgAlphaName, DisplayName: "Alpha"}
	orgBeta := &object.Organization{Owner: "admin", Name: orgBetaName, DisplayName: "Beta"}
	if ok, err := object.AddOrganization(orgAlpha); err != nil || !ok {
		t.Fatalf("failed to seed org alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(orgAlpha) })
	if ok, err := object.AddOrganization(orgBeta); err != nil || !ok {
		t.Fatalf("failed to seed org beta: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(orgBeta) })

	app := &object.Application{Owner: "admin", Name: appName, Organization: orgAlphaName, DisplayName: "Alpha App"}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("failed to seed application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	// Every organization needs at least one application for AddUser to
	// accept new users into it.
	appBeta := &object.Application{Owner: "admin", Name: "ctrl-test-app-beta-" + suffix, Organization: orgBetaName, DisplayName: "Beta App"}
	if ok, err := object.AddApplication(appBeta); err != nil || !ok {
		t.Fatalf("failed to seed beta application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(appBeta) })

	userAlpha := &object.User{Id: util.GenerateId(), Owner: orgAlphaName, Name: "alice-" + suffix, Password: "123"}
	if ok, err := object.AddUser(userAlpha, "en"); err != nil || !ok {
		t.Fatalf("failed to seed user alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { deleteControllerTestUser(t, userAlpha) })

	userBeta := &object.User{Id: util.GenerateId(), Owner: orgBetaName, Name: "bob-" + suffix, Password: "123"}
	if ok, err := object.AddUser(userBeta, "en"); err != nil || !ok {
		t.Fatalf("failed to seed user beta: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { deleteControllerTestUser(t, userBeta) })

	appIdentity := util.GetId("app", appName)

	// THE VIOLATION: app-alpha's own client credentials must not be able to
	// impersonate org beta's user via the "userId" query param.
	c := newTestApiController(appIdentity, "", "userId="+userBeta.GetId())
	user, ok := c.RequireSignedInUser()
	if ok && user != nil && user.GetId() == userBeta.GetId() {
		t.Fatalf("invariant violated: app %q (organization %q) was able to act as user %q from organization %q", appName, orgAlphaName, userBeta.GetId(), orgBetaName)
	}

	// GREEN CONTROL: the same app credentials must still be able to act as a
	// user within their own organization.
	c = newTestApiController(appIdentity, "", "userId="+userAlpha.GetId())
	user, ok = c.RequireSignedInUser()
	if !ok || user == nil || user.GetId() != userAlpha.GetId() {
		t.Fatalf("regression: app %q was denied the ability to act as its own organization %q's user %q", appName, orgAlphaName, userAlpha.GetId())
	}
}

// TestGetUserMasksSensitiveFieldsForOutOfOrgApp reproduces the TC-A2059D90
// trust assumption as it recurs one level deeper, inside GetUser
// (controllers/user.go): after CheckUserPermission scopes *whether* a
// profile is visible, GetUser separately computed
// isApplicationRequest := object.IsAppUser(requestUserId) and OR'd it
// unconditionally into isAdmin/isAdminOrSelf, unmasking every user's
// OriginalToken/OriginalRefreshToken/OAuth properties for any application's
// client credentials regardless of organization -- undoing the
// isGlobalAdmin/IsAdminOrSelf scoping fix within the very handler that
// relies on it. This only surfaces for a public-profile organization, where
// CheckUserPermission's own gate is intentionally skipped for everyone.
func TestGetUserMasksSensitiveFieldsForOutOfOrgApp(t *testing.T) {
	initAuthzScopeTestDb(t)

	suffix := util.GenerateId()[:8]
	orgAlphaName := "ctrl-test-org-alpha-" + suffix
	orgBetaName := "ctrl-test-org-beta-" + suffix
	appName := "ctrl-test-app-alpha-" + suffix

	orgAlpha := &object.Organization{Owner: "admin", Name: orgAlphaName, DisplayName: "Alpha"}
	orgBeta := &object.Organization{Owner: "admin", Name: orgBetaName, DisplayName: "Beta", IsProfilePublic: true}
	if ok, err := object.AddOrganization(orgAlpha); err != nil || !ok {
		t.Fatalf("failed to seed org alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(orgAlpha) })
	if ok, err := object.AddOrganization(orgBeta); err != nil || !ok {
		t.Fatalf("failed to seed org beta: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(orgBeta) })

	app := &object.Application{Owner: "admin", Name: appName, Organization: orgAlphaName, DisplayName: "Alpha App"}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("failed to seed application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	appBeta := &object.Application{Owner: "admin", Name: "ctrl-test-app-beta-" + suffix, Organization: orgBetaName, DisplayName: "Beta App"}
	if ok, err := object.AddApplication(appBeta); err != nil || !ok {
		t.Fatalf("failed to seed beta application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(appBeta) })

	const secretToken = "victim-oauth-access-token-should-never-leak"
	userBeta := &object.User{Id: util.GenerateId(), Owner: orgBetaName, Name: "bob-" + suffix, Password: "123", OriginalToken: secretToken}
	if ok, err := object.AddUser(userBeta, "en"); err != nil || !ok {
		t.Fatalf("failed to seed user beta: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { deleteControllerTestUser(t, userBeta) })

	const ownToken = "alpha-oauth-access-token-should-still-be-visible"
	userAlpha := &object.User{Id: util.GenerateId(), Owner: orgAlphaName, Name: "alice-" + suffix, Password: "123", OriginalToken: ownToken}
	if ok, err := object.AddUser(userAlpha, "en"); err != nil || !ok {
		t.Fatalf("failed to seed user alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { deleteControllerTestUser(t, userAlpha) })

	appIdentity := util.GetId("app", appName)

	// THE VIOLATION: app-alpha's own client credentials, reading org beta's
	// (public-profile) user, must see OriginalToken masked -- app-alpha is
	// not org beta's admin.
	c, rec := newTestApiControllerWithRecorder(appIdentity, orgBetaName, "id="+userBeta.GetId())
	c.GetUser()

	var resp struct {
		Data struct {
			OriginalToken string `json:"originalToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse GetUser response %q: %v", rec.Body.String(), err)
	}
	if resp.Data.OriginalToken == secretToken {
		t.Fatalf("invariant violated: app %q (organization %q) received unmasked OriginalToken for organization %q's user via GetUser", appName, orgAlphaName, orgBetaName)
	}

	// GREEN CONTROL: app-alpha's own client credentials must still see its
	// own organization's user unmasked (legitimate same-tenant SDK usage).
	c, rec = newTestApiControllerWithRecorder(appIdentity, orgAlphaName, "id="+userAlpha.GetId())
	c.GetUser()
	resp.Data.OriginalToken = ""
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse GetUser response %q: %v", rec.Body.String(), err)
	}
	if resp.Data.OriginalToken != ownToken {
		t.Fatalf("regression: app %q was denied its own organization %q's user OriginalToken via GetUser (got %q)", appName, orgAlphaName, resp.Data.OriginalToken)
	}
}

func deleteControllerTestUser(t *testing.T, user *object.User) {
	t.Helper()
	if _, err := object.DeleteUser(user); err != nil {
		t.Logf("cleanup: failed to delete user %s: %v", user.GetId(), err)
	}
}
