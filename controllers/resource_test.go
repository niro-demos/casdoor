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
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// newTestApiController builds a minimal, fully wired ApiController for a
// GET request, with the signed-in user set exactly the way the real
// production auth filter sets it (routers/authz_filter.go calls
// ctx.Input.SetData("currentUserId", username)), so GetSessionUsername()
// resolves it without needing a real HTTP session/cookie stack.
func newTestApiController(rawURL string, currentUserId string) *ApiController {
	req := httptest.NewRequest("GET", rawURL, nil)
	w := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetResources", nil)
	if currentUserId != "" {
		c.Ctx.Input.SetData("currentUserId", currentUserId)
	}
	return c
}

// resourceKey builds the same "owner|user|name" identifier used both when
// seeding a resource and when checking whether it showed up in a response,
// so the two never drift out of sync over an accidental "/" in Name (all
// test resource names below start with a leading "/").
func resourceKey(owner, user, name string) string {
	return owner + "|" + user + "|" + name
}

// resourceKeys returns the set of resourceKey() identifiers present in a
// GetResources() JSON response payload, for easy membership assertions.
func resourceKeys(t *testing.T, data interface{}) map[string]bool {
	t.Helper()
	resources, ok := data.([]*object.Resource)
	if !ok {
		t.Fatalf("response data is not []*object.Resource: %#v", data)
	}
	keys := map[string]bool{}
	for _, r := range resources {
		keys[resourceKey(r.Owner, r.User, r.Name)] = true
	}
	return keys
}

// TestGetResourcesEnforcesCallerScopeForStandardUser is the regression test
// for TC-28B85E61: GET /api/get-resources let any authenticated standard
// (non-admin) user list other users' and other organizations' resource
// records by supplying arbitrary owner/user query parameters, because the
// controller never re-derived owner/user from the caller's own identity for
// non-admins, and object.GetResources() additionally treated
// owner=="built-in" or owner=="" as "scan every organization".
//
// Invariant under test: a standard, non-admin user must not be able to list
// resource records belonging to a different user or a different
// organization via GET /api/get-resources, regardless of what owner/user
// query parameters it is given.
func TestGetResourcesEnforcesCallerScopeForStandardUser(t *testing.T) {
	object.InitConfig()

	victimOrg := "tc28b85e61-org"
	otherOrg := "tc28b85e61-other-org"

	seedTestOrganization(t, victimOrg)
	seedTestOrganization(t, otherOrg)
	seedTestUser(t, victimOrg, "alice", false)
	seedTestUser(t, victimOrg, "bob", false)

	aliceResourceName := "/tc28b85e61-alice-file.txt"
	bobResourceName := "/tc28b85e61-bob-secret.jpg"
	otherOrgResourceName := "/tc28b85e61-other-org-file.txt"

	seedTestResource(t, victimOrg, "alice", aliceResourceName)
	seedTestResource(t, victimOrg, "bob", bobResourceName)
	seedTestResource(t, otherOrg, "carol", otherOrgResourceName)

	aliceSession := victimOrg + "/alice"

	// --- Legitimate case: alice can still list her own resources. ---
	legit := newTestApiController("/api/get-resources?owner="+victimOrg+"&user=alice", aliceSession)
	legit.GetResources()
	legitResp, ok := legit.Data["json"].(*Response)
	if !ok || legitResp.Status != "ok" {
		t.Fatalf("baseline broken: alice could not list her own resources: %#v", legit.Data["json"])
	}
	if keys := resourceKeys(t, legitResp.Data); !keys[resourceKey(victimOrg, "alice", aliceResourceName)] {
		t.Fatalf("alice's own resource missing from her own listing: %v", keys)
	}

	// --- Vulnerable case 1: alice asks for bob's resources by name. ---
	crossUser := newTestApiController("/api/get-resources?owner="+victimOrg+"&user=bob", aliceSession)
	crossUser.GetResources()
	crossUserResp, ok := crossUser.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", crossUser.Data["json"])
	}
	if crossUserResp.Status == "ok" {
		if keys := resourceKeys(t, crossUserResp.Data); keys[resourceKey(victimOrg, "bob", bobResourceName)] {
			t.Fatalf("VULNERABLE: alice (standard user) was able to list bob's resource via owner/user query params: %v", keys)
		}
	}

	// --- Vulnerable case 2: alice asks for owner=built-in (the object-layer
	// "scan every organization" trigger), expecting to see everyone's data. ---
	crossOrg := newTestApiController("/api/get-resources?owner=built-in&user=admin", aliceSession)
	crossOrg.GetResources()
	crossOrgResp, ok := crossOrg.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", crossOrg.Data["json"])
	}
	if crossOrgResp.Status == "ok" {
		keys := resourceKeys(t, crossOrgResp.Data)
		if keys[resourceKey(victimOrg, "bob", bobResourceName)] {
			t.Fatalf("VULNERABLE: alice was able to list bob's resource via owner=built-in: %v", keys)
		}
		if keys[resourceKey(otherOrg, "carol", otherOrgResourceName)] {
			t.Fatalf("VULNERABLE: alice was able to list another organization's resource via owner=built-in: %v", keys)
		}
	}

	// --- Vulnerable case 3: alice asks with no query params at all. ---
	noParams := newTestApiController("/api/get-resources", aliceSession)
	noParams.GetResources()
	noParamsResp, ok := noParams.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", noParams.Data["json"])
	}
	if noParamsResp.Status == "ok" {
		keys := resourceKeys(t, noParamsResp.Data)
		if keys[resourceKey(victimOrg, "bob", bobResourceName)] {
			t.Fatalf("VULNERABLE: alice was able to list bob's resource with no query params: %v", keys)
		}
		if keys[resourceKey(otherOrg, "carol", otherOrgResourceName)] {
			t.Fatalf("VULNERABLE: alice was able to list another organization's resource with no query params: %v", keys)
		}
	}
}

// TestGetResourcesGlobalAdminStillSeesAllOrganizations is a positive control
// proving the fix does not regress the legitimate global-admin "view all
// resources across all organizations" workflow (the Casdoor web UI's
// Resources page, when "All organizations" is selected, calls
// GET /api/get-resources?owner=&user=<admin-name>).
func TestGetResourcesGlobalAdminStillSeesAllOrganizations(t *testing.T) {
	object.InitConfig()

	adminOrg := "built-in"
	victimOrg := "tc28b85e61-admin-org"

	seedTestUser(t, adminOrg, "tc28b85e61-admin", true)
	seedTestResource(t, victimOrg, "dave", "/tc28b85e61-dave-file.txt")

	adminSession := adminOrg + "/tc28b85e61-admin"

	all := newTestApiController("/api/get-resources?owner=&user=tc28b85e61-admin", adminSession)
	all.GetResources()
	allResp, ok := all.Data["json"].(*Response)
	if !ok || allResp.Status != "ok" {
		t.Fatalf("global admin listing failed: %#v", all.Data["json"])
	}
	keys := resourceKeys(t, allResp.Data)
	if !keys[resourceKey(victimOrg, "dave", "/tc28b85e61-dave-file.txt")] {
		t.Fatalf("global admin no longer sees resources from other organizations (regression in admin workflow): %v", keys)
	}
}

func seedTestUser(t *testing.T, owner, name string, isAdmin bool) {
	t.Helper()
	existing, err := object.GetUser(owner + "/" + name)
	if err != nil {
		t.Fatalf("failed to check for existing test user %s/%s: %v", owner, name, err)
	}
	if existing != nil {
		return
	}

	user := &object.User{
		Owner:   owner,
		Name:    name,
		Id:      owner + "-" + name + "-tc28b85e61",
		IsAdmin: isAdmin,
	}
	// AddUsers() is the syncer/batch-upload insert path: unlike AddUser(), it
	// doesn't run signup-flow business rules (e.g. the "built-in" org signup
	// guard), so it seeds a plain user row for either org used by this test.
	affected, err := object.AddUsers([]*object.User{user})
	if err != nil || !affected {
		t.Fatalf("failed to seed test user %s/%s: affected=%v err=%v", owner, name, affected, err)
	}
	// Deliberately not cleaned up via object.DeleteUser(): that call requires
	// the package-level user/group enforcer to be initialized from seed data
	// this bare test database doesn't have. The "existing != nil" check above
	// makes reseeding idempotent across repeated test runs instead.
}

func seedTestOrganization(t *testing.T, name string) {
	t.Helper()
	existing, err := object.GetOrganization("admin/" + name)
	if err != nil {
		t.Fatalf("failed to check for existing test organization %s: %v", name, err)
	}
	if existing != nil {
		return
	}

	org := &object.Organization{
		Owner: "admin",
		Name:  name,
	}
	affected, err := object.AddOrganization(org)
	if err != nil || !affected {
		t.Fatalf("failed to seed test organization %s: affected=%v err=%v", name, affected, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteOrganization(org)
	})
}

func seedTestResource(t *testing.T, owner, user, name string) {
	t.Helper()
	resource := &object.Resource{
		Owner:       owner,
		Name:        name,
		CreatedTime: "2026-01-01T00:00:00Z",
		User:        user,
		Provider:    "tc28b85e61-provider",
		Application: "admin/app-tc28b85e61",
		Tag:         "tc28b85e61",
		Url:         "https://example.com/tc28b85e61/" + user + name,
	}
	affected, err := object.AddResource(resource)
	if err != nil || !affected {
		t.Fatalf("failed to seed test resource %s/%s%s: affected=%v err=%v", owner, user, name, affected, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteResource(resource)
	})
}
