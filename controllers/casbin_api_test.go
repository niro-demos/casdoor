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

//go:build !skipCi

package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var initTestBackendOnce sync.Once

// initTestBackend brings up the same object-layer state main.go does before
// serving requests (DB connection/schema, built-in casbin models/enforcers,
// and the in-memory user-group enforcer GetAllRoles's callers rely on). It
// is idempotent at the DB level (existing built-ins are left alone) and only
// runs once per test binary.
func initTestBackend() {
	initTestBackendOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
		object.InitUserManager()
	})
}

// Regression test for TC-B296235F.
//
// Invariant under test: a logged-in, non-admin user must not be able to read
// the role membership of a user in a different organization/tenant just by
// passing that user's id via the `userId` query parameter on
// GET /api/get-all-roles (and, sharing the identical vulnerable pattern,
// /api/get-all-objects and /api/get-all-actions). The caller's own (self)
// lookup must keep working.

const (
	tcB296235FOwnOrg     = "tcb296235f-alpha"
	tcB296235FForeignOrg = "tcb296235f-beta"
)

// setupCrossTenantRoleFixture seeds two disposable organizations (each with
// the one application AddUser requires), a non-admin user in each, and a
// role in the "foreign" org referencing the foreign user - mirroring the
// PoC's own fixture. It returns a cleanup func that removes everything it
// created.
func setupCrossTenantRoleFixture(t *testing.T) func() {
	t.Helper()

	initTestBackend()

	ownOrg := &object.Organization{Owner: "admin", Name: tcB296235FOwnOrg, DisplayName: tcB296235FOwnOrg}
	foreignOrg := &object.Organization{Owner: "admin", Name: tcB296235FForeignOrg, DisplayName: tcB296235FForeignOrg}
	if _, err := object.AddOrganization(ownOrg); err != nil {
		t.Fatalf("failed to seed organization %s: %v", tcB296235FOwnOrg, err)
	}
	if _, err := object.AddOrganization(foreignOrg); err != nil {
		t.Fatalf("failed to seed organization %s: %v", tcB296235FForeignOrg, err)
	}

	ownApp := &object.Application{Owner: "admin", Name: "app-" + tcB296235FOwnOrg, Organization: tcB296235FOwnOrg}
	foreignApp := &object.Application{Owner: "admin", Name: "app-" + tcB296235FForeignOrg, Organization: tcB296235FForeignOrg}
	if _, err := object.AddApplication(ownApp); err != nil {
		t.Fatalf("failed to seed application for %s: %v", tcB296235FOwnOrg, err)
	}
	if _, err := object.AddApplication(foreignApp); err != nil {
		t.Fatalf("failed to seed application for %s: %v", tcB296235FForeignOrg, err)
	}

	bob := &object.User{Owner: tcB296235FOwnOrg, Name: "bob", Id: util.GenerateId(), Password: "NiroPass123"}
	carol := &object.User{Owner: tcB296235FOwnOrg, Name: "carol", Id: util.GenerateId(), Password: "NiroPass123"}
	alice := &object.User{Owner: tcB296235FForeignOrg, Name: "alice", Id: util.GenerateId(), Password: "NiroPass123"}
	if _, err := object.AddUser(bob, "en"); err != nil {
		t.Fatalf("failed to seed user bob: %v", err)
	}
	if _, err := object.AddUser(carol, "en"); err != nil {
		t.Fatalf("failed to seed user carol: %v", err)
	}
	if _, err := object.AddUser(alice, "en"); err != nil {
		t.Fatalf("failed to seed user alice: %v", err)
	}

	role := &object.Role{
		Owner:       tcB296235FForeignOrg,
		Name:        "vector-crosstenant-role",
		DisplayName: "vector-crosstenant-role",
		Users:       []string{tcB296235FForeignOrg + "/alice"},
		Roles:       []string{},
	}
	if _, err := object.AddRole(role); err != nil {
		t.Fatalf("failed to seed role: %v", err)
	}

	return func() {
		_, _ = object.DeleteRole(role)
		_, _ = object.DeleteUser(bob)
		_, _ = object.DeleteUser(carol)
		_, _ = object.DeleteUser(alice)
		_, _ = object.DeleteApplication(ownApp)
		_, _ = object.DeleteApplication(foreignApp)
		_, _ = object.DeleteOrganization(ownOrg)
		_, _ = object.DeleteOrganization(foreignOrg)
	}
}

// newTestApiController builds an ApiController wired to an httptest request
// and response recorder, and stashes sessionUserId as the authenticated
// caller the same way routers.ApiFilter does via
// ctx.Input.SetData("currentUserId", ...) after a successful login.
func newTestApiController(method, target, sessionUserId string) (*ApiController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()

	ctx := context.NewContext()
	ctx.Reset(w, req)
	if sessionUserId != "" {
		ctx.Input.SetData("currentUserId", sessionUserId)
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetAllRoles", nil)

	return c, w
}

func TestGetAllRolesRejectsCrossTenantUserId(t *testing.T) {
	cleanup := setupCrossTenantRoleFixture(t)
	defer cleanup()

	bobId := tcB296235FOwnOrg + "/bob"
	aliceId := tcB296235FForeignOrg + "/alice"

	// Vulnerable call: bob (own org, non-admin) asks for alice's roles
	// (a different org) via the userId query parameter.
	c, w := newTestApiController(http.MethodGet, "/api/get-all-roles?userId="+aliceId, bobId)
	c.GetAllRoles()

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not parse response: %v\nraw: %s", err, w.Body.String())
	}

	if resp.Status == "ok" {
		t.Fatalf("SECURITY: cross-tenant GET /api/get-all-roles?userId=%s as %s disclosed data instead of being rejected: %+v", aliceId, bobId, resp)
	}

	// Positive control: bob's own (self) lookup must keep working, proving
	// the rejection above is the tenant-isolation invariant and not a
	// broken test environment.
	c2, w2 := newTestApiController(http.MethodGet, "/api/get-all-roles", bobId)
	c2.GetAllRoles()

	var selfResp Response
	if err := json.Unmarshal(w2.Body.Bytes(), &selfResp); err != nil {
		t.Fatalf("could not parse self response: %v\nraw: %s", err, w2.Body.String())
	}
	if selfResp.Status != "ok" {
		t.Fatalf("CONTROL FAILED (environment suspect): bob's own GET /api/get-all-roles (legitimate, no userId) should succeed: %+v", selfResp)
	}
}

// TestGetAllRolesPreservesLegitimateAccess guards against the fix
// over-narrowing: it was not established anywhere that same-organization,
// non-self lookups (any logged-in user looking up a teammate) or a global
// admin's cross-tenant lookups needed to be restricted, so both must keep
// working exactly as they did before the fix.
func TestGetAllRolesPreservesLegitimateAccess(t *testing.T) {
	cleanup := setupCrossTenantRoleFixture(t)
	defer cleanup()

	carolId := tcB296235FOwnOrg + "/carol"
	aliceId := tcB296235FForeignOrg + "/alice"

	// Same-organization, non-self lookup: bob asking about carol (both in
	// tcB296235FOwnOrg) is unrelated to the cross-tenant invariant and must
	// still succeed.
	c, w := newTestApiController(http.MethodGet, "/api/get-all-roles?userId="+carolId, tcB296235FOwnOrg+"/bob")
	c.GetAllRoles()

	var sameOrgResp Response
	if err := json.Unmarshal(w.Body.Bytes(), &sameOrgResp); err != nil {
		t.Fatalf("could not parse same-org response: %v\nraw: %s", err, w.Body.String())
	}
	if sameOrgResp.Status != "ok" {
		t.Fatalf("REGRESSION: same-organization lookup (bob -> carol) was rejected, but only cross-tenant lookups should be: %+v", sameOrgResp)
	}

	// Global admin cross-tenant lookup: a global admin legitimately needs to
	// inspect any organization's authorization data.
	c2, w2 := newTestApiController(http.MethodGet, "/api/get-all-roles?userId="+aliceId, "built-in/admin")
	c2.GetAllRoles()

	var adminResp Response
	if err := json.Unmarshal(w2.Body.Bytes(), &adminResp); err != nil {
		t.Fatalf("could not parse admin response: %v\nraw: %s", err, w2.Body.String())
	}
	if adminResp.Status != "ok" {
		t.Fatalf("REGRESSION: global admin cross-tenant lookup was rejected: %+v", adminResp)
	}
}
