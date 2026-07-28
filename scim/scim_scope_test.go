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

// Regression test for TC-A2F26A42: the SCIM provisioning API (HandleScim in
// controllers/scim.go, backed by UserResourceHandler / GroupResourceHandler
// here) let any isAdmin=true user - even one scoped to a single organization
// - view, create, and delete identities belonging to every other organization
// on the instance, because the caller's organization scope was discarded
// instead of being enforced on every operation.
//
// Invariant under test: an administrator of one organization must not be
// able to view, list, create, or delete user and group identities that
// belong to a different organization through the SCIM provisioning API,
// while the built-in global admin (the intended bypass) keeps full access.

package scim

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
)

// requestWithOwner builds an *http.Request carrying the SCIM caller's
// organization scope the same way controllers.HandleScim does via
// scim.WithOwner. scoped=false simulates the built-in global admin (no
// context value set - ownerFromRequest returns "", false).
func requestWithOwner(owner string, scoped bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/Users", nil)
	if !scoped {
		return req
	}
	return req.WithContext(WithOwner(req.Context(), owner))
}

// setupScopeOrg creates an isolated organization with one application and one
// seed user (object.AddUser requires both to exist), and registers cleanup so
// none of it lingers past the test.
func setupScopeOrg(t *testing.T, name string) *object.User {
	t.Helper()

	org := &object.Organization{Owner: "admin", Name: name, DisplayName: name, PasswordType: "plain"}
	ok, err := object.AddOrganization(org)
	if err != nil || !ok {
		t.Fatalf("setup: failed to create organization %s: ok=%v err=%v", name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(org) })

	app := &object.Application{Owner: "admin", Name: name + "-app", Organization: name, DisplayName: name + " app"}
	ok, err = object.AddApplication(app)
	if err != nil || !ok {
		t.Fatalf("setup: failed to create application for %s: ok=%v err=%v", name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	user := &object.User{
		Owner:       name,
		Name:        "seed-user",
		DisplayName: "Seed User",
		Password:    "Passw0rd!23",
		Email:       fmt.Sprintf("%s-seed@example.com", name),
	}
	ok, err = object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("setup: failed to create seed user for %s: ok=%v err=%v", name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

func assertNotFoundScimError(t *testing.T, context string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected a SCIM error, got nil (invariant violated)", context)
	}
	scimErr, ok := err.(scimerrors.ScimError)
	if !ok || scimErr.Status != http.StatusNotFound {
		t.Fatalf("%s: expected a 404 SCIM error, got %#v", context, err)
	}
}

// TestSCIMUserOrganizationScope is the regression test for the SCIM User
// resource handler half of TC-A2F26A42.
func TestSCIMUserOrganizationScope(t *testing.T) {
	object.InitConfig()
	object.InitUserManager()

	suffix := time.Now().UnixNano()
	orgA := fmt.Sprintf("scimscopeusera%d", suffix)
	orgB := fmt.Sprintf("scimscopeuserb%d", suffix)

	userA := setupScopeOrg(t, orgA)
	userB := setupScopeOrg(t, orgB)

	h := UserResourceHandler{}
	reqScopedA := requestWithOwner(orgA, true)

	// Positive control: an org-A-scoped caller can read its own org's user.
	res, err := h.Get(reqScopedA, userA.Id)
	if err != nil {
		t.Fatalf("control: org-A admin failed to read its own user via SCIM: %v", err)
	}
	if res.ID != userA.Id {
		t.Fatalf("control: expected to read %s, got %s", userA.Id, res.ID)
	}

	// Invariant (read): an org-A-scoped caller must NOT be able to read a
	// user belonging to org B via SCIM Get.
	_, err = h.Get(reqScopedA, userB.Id)
	assertNotFoundScimError(t, "GET cross-org user", err)

	// Invariant (list): GetAll for an org-A-scoped caller must only return
	// org A's users, never org B's.
	page, err := h.GetAll(reqScopedA, scim.ListRequestParams{StartIndex: 1, Count: 100})
	if err != nil {
		t.Fatalf("org-A admin GetAll (users) failed: %v", err)
	}
	foundOwn := false
	for _, resource := range page.Resources {
		if resource.ID == userB.Id {
			t.Fatalf("invariant violated: org-A admin's SCIM Users listing included org-B user %s", userB.Id)
		}
		if resource.ID == userA.Id {
			foundOwn = true
		}
	}
	if !foundOwn {
		t.Fatalf("org-A admin's SCIM Users listing did not include its own user %s", userA.Id)
	}

	// Invariant (delete): an org-A-scoped caller must NOT be able to delete a
	// user belonging to org B, and the user must survive the attempt.
	err = h.Delete(reqScopedA, userB.Id)
	assertNotFoundScimError(t, "DELETE cross-org user", err)
	if stillThere, gerr := object.GetUserByUserIdOnly(userB.Id); gerr != nil || stillThere == nil {
		t.Fatalf("org-B user was deleted (or lookup failed) after a rejected cross-org SCIM delete: err=%v user=%v", gerr, stillThere)
	}

	// Invariant (create): an org-A-scoped caller must NOT be able to create a
	// user inside org B via SCIM.
	// Extension attributes arrive from the SCIM library as a plain
	// map[string]interface{} (that's what json.Unmarshal produces for a
	// nested object) - use that concrete type here too, not the named
	// scim.ResourceAttributes, so this exercises the same code path as a
	// real request instead of tripping the library's own type assertion.
	crossOrgUserName := fmt.Sprintf("crossorg-%d", suffix)
	crossOrgAttrs := scim.ResourceAttributes{
		"userName":    crossOrgUserName,
		"displayName": "Cross Org Attempt",
		UserExtensionKey: map[string]interface{}{
			"organization": orgB,
		},
	}
	_, err = h.Create(reqScopedA, crossOrgAttrs)
	if err == nil {
		t.Fatalf("invariant violated: org-A admin created a user inside org B via SCIM")
	}
	if forbiddenErr, ok := err.(scimerrors.ScimError); !ok || forbiddenErr.Status != http.StatusForbidden {
		t.Fatalf("expected a 403 SCIM error rejecting the cross-org create, got %#v", err)
	}
	if created, gerr := object.GetUser(orgB + "/" + crossOrgUserName); gerr == nil && created != nil {
		_, _ = object.DeleteUser(created)
		t.Fatalf("invariant violated: cross-org user %s was persisted despite the rejected SCIM create", created.GetId())
	}

	// Control: the built-in global admin (unscoped caller) can still read
	// across organizations - the intended bypass must keep working.
	reqGlobal := requestWithOwner("", false)
	res, err = h.Get(reqGlobal, userB.Id)
	if err != nil {
		t.Fatalf("control: global admin failed to read org-B user via SCIM: %v", err)
	}
	if res.ID != userB.Id {
		t.Fatalf("control: global admin read the wrong resource: got %s want %s", res.ID, userB.Id)
	}
}

// TestSCIMGroupOrganizationScope is the regression test for the SCIM Group
// resource handler half of TC-A2F26A42.
func TestSCIMGroupOrganizationScope(t *testing.T) {
	object.InitConfig()
	object.InitUserManager()

	suffix := time.Now().UnixNano()
	orgA := fmt.Sprintf("scimscopegroupa%d", suffix)
	orgB := fmt.Sprintf("scimscopegroupb%d", suffix)

	groupA := &object.Group{Owner: orgA, Name: "team-a", DisplayName: "Team A", IsTopGroup: true, IsEnabled: true}
	ok, err := object.AddGroup(groupA)
	if err != nil || !ok {
		t.Fatalf("setup: failed to create group A: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteGroup(groupA) })

	groupB := &object.Group{Owner: orgB, Name: "team-b", DisplayName: "Team B", IsTopGroup: true, IsEnabled: true}
	ok, err = object.AddGroup(groupB)
	if err != nil || !ok {
		t.Fatalf("setup: failed to create group B: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteGroup(groupB) })

	h := GroupResourceHandler{}
	idA, idB := groupA.GetId(), groupB.GetId()
	reqScopedA := requestWithOwner(orgA, true)

	// Positive control: an org-A-scoped caller can read its own org's group.
	res, err := h.Get(reqScopedA, idA)
	if err != nil {
		t.Fatalf("control: org-A admin failed to read its own group via SCIM: %v", err)
	}
	if res.ID != idA {
		t.Fatalf("control: expected to read %s, got %s", idA, res.ID)
	}

	// Invariant (read): an org-A-scoped caller must NOT be able to read a
	// group belonging to org B via SCIM Get.
	_, err = h.Get(reqScopedA, idB)
	assertNotFoundScimError(t, "GET cross-org group", err)

	// Invariant (list): GetAll for an org-A-scoped caller must only return
	// org A's groups, never org B's.
	page, err := h.GetAll(reqScopedA, scim.ListRequestParams{StartIndex: 1, Count: 100})
	if err != nil {
		t.Fatalf("org-A admin GetAll (groups) failed: %v", err)
	}
	foundOwn := false
	for _, resource := range page.Resources {
		if resource.ID == idB {
			t.Fatalf("invariant violated: org-A admin's SCIM Groups listing included org-B group %s", idB)
		}
		if resource.ID == idA {
			foundOwn = true
		}
	}
	if !foundOwn {
		t.Fatalf("org-A admin's SCIM Groups listing did not include its own group %s", idA)
	}

	// Invariant (delete): an org-A-scoped caller must NOT be able to delete a
	// group belonging to org B, and the group must survive the attempt.
	err = h.Delete(reqScopedA, idB)
	assertNotFoundScimError(t, "DELETE cross-org group", err)
	if stillThere, gerr := object.GetGroup(idB); gerr != nil || stillThere == nil {
		t.Fatalf("org-B group was deleted (or lookup failed) after a rejected cross-org SCIM delete: err=%v group=%v", gerr, stillThere)
	}

	// Invariant (create): an org-A-scoped caller must NOT be able to create a
	// group inside org B via SCIM (mirrors the PoC's Groups?organization=built-in step).
	crossOrgGroupName := fmt.Sprintf("CrossOrgAttempt%d", suffix)
	crossOrgAttrs := scim.ResourceAttributes{
		"displayName": crossOrgGroupName,
		// A plain map[string]interface{}, matching what json.Unmarshal
		// produces for a nested object in a real request (see the User
		// test's identical comment above).
		GroupExtensionKey: map[string]interface{}{
			"organization": orgB,
		},
	}
	_, err = h.Create(reqScopedA, crossOrgAttrs)
	if err == nil {
		t.Fatalf("invariant violated: org-A admin created a group inside org B via SCIM")
	}
	if forbiddenErr, ok := err.(scimerrors.ScimError); !ok || forbiddenErr.Status != http.StatusForbidden {
		t.Fatalf("expected a 403 SCIM error rejecting the cross-org create, got %#v", err)
	}
	crossOrgId := orgB + "/" + crossOrgGroupName
	if created, gerr := object.GetGroup(crossOrgId); gerr == nil && created != nil {
		_, _ = object.DeleteGroup(created)
		t.Fatalf("invariant violated: cross-org group %s was persisted despite the rejected SCIM create", created.GetId())
	}

	// Control: the built-in global admin (unscoped caller) can still read
	// across organizations - the intended bypass must keep working.
	reqGlobal := requestWithOwner("", false)
	res, err = h.Get(reqGlobal, idB)
	if err != nil {
		t.Fatalf("control: global admin failed to read org-B group via SCIM: %v", err)
	}
	if res.ID != idB {
		t.Fatalf("control: global admin read the wrong resource: got %s want %s", res.ID, idB)
	}
}
