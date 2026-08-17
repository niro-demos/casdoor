// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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

package scim

// Regression test for TC-50C96734: the SCIM Users API let any org-scoped
// admin (Casdoor IsAdmin=true but not the built-in global admin) read,
// enumerate, and mutate user accounts belonging to OTHER organizations,
// because the caller's organization was resolved by RequireAdmin() and then
// discarded before reaching scim/user_handler.go. These tests exercise
// UserResourceHandler directly (the same code HandleScim forwards into)
// against a real, seeded database so they capture exactly the same
// invariant the PoC in niro/findings/TC-50C96734/poc.go proved was broken:
//
//   An organization admin scoped to org A must not be able to read,
//   enumerate, or modify a user belonging to org B via SCIM. The
//   unrestricted built-in global admin (owner == "") must retain full
//   access, matching RequireAdmin()'s existing contract.

import (
	"context"
	"net/http"
	"testing"

	"github.com/casdoor/casdoor/object"
	elimityscim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
)

// scimOrgScopeFixture holds two isolated organizations, one user in each, set
// up against the project's real test database (see object.InitConfig) and
// torn down after the test.
type scimOrgScopeFixture struct {
	orgA, orgB   *object.Organization
	appA, appB   *object.Application
	userA, userB *object.User
}

func setupScimOrgScopeFixture(t *testing.T) *scimOrgScopeFixture {
	t.Helper()
	object.InitConfig()
	object.InitUserManager()

	suffix := "nirotc50c96734"
	orgAName := "scimtest-orga-" + suffix
	orgBName := "scimtest-orgb-" + suffix

	f := &scimOrgScopeFixture{
		orgA: &object.Organization{Owner: "admin", Name: orgAName, DisplayName: orgAName},
		orgB: &object.Organization{Owner: "admin", Name: orgBName, DisplayName: orgBName},
	}
	if ok, err := object.AddOrganization(f.orgA); err != nil || !ok {
		t.Fatalf("failed to seed organization %s: ok=%v err=%v", orgAName, ok, err)
	}
	if ok, err := object.AddOrganization(f.orgB); err != nil || !ok {
		t.Fatalf("failed to seed organization %s: ok=%v err=%v", orgBName, ok, err)
	}

	f.appA = &object.Application{Owner: "admin", Name: "app-" + orgAName, Organization: orgAName, DisplayName: "app-" + orgAName}
	f.appB = &object.Application{Owner: "admin", Name: "app-" + orgBName, Organization: orgBName, DisplayName: "app-" + orgBName}
	if ok, err := object.AddApplication(f.appA); err != nil || !ok {
		t.Fatalf("failed to seed application for %s: ok=%v err=%v", orgAName, ok, err)
	}
	if ok, err := object.AddApplication(f.appB); err != nil || !ok {
		t.Fatalf("failed to seed application for %s: ok=%v err=%v", orgBName, ok, err)
	}

	f.userA = &object.User{
		Owner: orgAName, Name: "alice-" + suffix, Id: "scimid-a-" + suffix,
		DisplayName: "Alice A", Email: "alice-" + suffix + "@example.com", Password: "NiroPass123!",
	}
	f.userB = &object.User{
		Owner: orgBName, Name: "bob-" + suffix, Id: "scimid-b-" + suffix,
		DisplayName: "Bob B", Email: "bob-" + suffix + "@example.com", Password: "NiroPass123!",
	}
	if ok, err := object.AddUser(f.userA, "en"); err != nil || !ok {
		t.Fatalf("failed to seed user %s: ok=%v err=%v", f.userA.Id, ok, err)
	}
	if ok, err := object.AddUser(f.userB, "en"); err != nil || !ok {
		t.Fatalf("failed to seed user %s: ok=%v err=%v", f.userB.Id, ok, err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteUser(f.userA)
		_, _ = object.DeleteUser(f.userB)
		_, _ = object.DeleteApplication(f.appA)
		_, _ = object.DeleteApplication(f.appB)
		_, _ = object.DeleteOrganization(f.orgA)
		_, _ = object.DeleteOrganization(f.orgB)
	})

	return f
}

// requestAsOwner builds an *http.Request carrying the caller organization the
// way controllers.HandleScim is expected to attach it (see OwnerContextKey):
// "" for the unrestricted built-in global admin, or the caller's own
// organization name for an org-scoped admin.
func requestAsOwner(owner string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/Users", nil)
	return req.WithContext(context.WithValue(req.Context(), OwnerContextKey, owner))
}

func isScimNotFound(err error) bool {
	scimErr, ok := err.(scimerrors.ScimError)
	return ok && scimErr.Status == http.StatusNotFound
}

func TestUserResourceHandlerGetEnforcesOrgScope(t *testing.T) {
	f := setupScimOrgScopeFixture(t)
	h := UserResourceHandler{}

	// An org-scoped admin of orgA must be denied when reading a user that
	// belongs to orgB.
	_, err := h.Get(requestAsOwner(f.orgA.Name), f.userB.Id)
	if err == nil {
		t.Fatalf("VIOLATION: org-scoped admin of %q was able to read cross-tenant user %q via SCIM Get", f.orgA.Name, f.userB.Id)
	}
	if !isScimNotFound(err) {
		t.Fatalf("expected a 404 ScimError for cross-tenant Get, got: %v", err)
	}

	// Positive control: the same admin reading a user in their own org must
	// still succeed, proving the failure above is tenant-scoping and not a
	// broken handler/environment.
	resource, err := h.Get(requestAsOwner(f.orgA.Name), f.userA.Id)
	if err != nil {
		t.Fatalf("same-tenant SCIM Get unexpectedly failed: %v", err)
	}
	if resource.ID != f.userA.Id {
		t.Fatalf("same-tenant SCIM Get returned wrong resource: got %q want %q", resource.ID, f.userA.Id)
	}

	// The unrestricted built-in global admin (owner == "") must retain
	// cross-org access.
	resource, err = h.Get(requestAsOwner(""), f.userB.Id)
	if err != nil {
		t.Fatalf("global admin SCIM Get unexpectedly failed: %v", err)
	}
	if resource.ID != f.userB.Id {
		t.Fatalf("global admin SCIM Get returned wrong resource: got %q want %q", resource.ID, f.userB.Id)
	}
}

func TestUserResourceHandlerGetAllEnforcesOrgScope(t *testing.T) {
	f := setupScimOrgScopeFixture(t)
	h := UserResourceHandler{}

	page, err := h.GetAll(requestAsOwner(f.orgA.Name), elimityscim.ListRequestParams{Count: 100, StartIndex: 1})
	if err != nil {
		t.Fatalf("SCIM GetAll unexpectedly failed: %v", err)
	}
	for _, resource := range page.Resources {
		if resource.ID == f.userB.Id {
			t.Fatalf("VIOLATION: org-scoped admin of %q enumerated cross-tenant user %q via SCIM GetAll", f.orgA.Name, f.userB.Id)
		}
	}
	sawOwnUser := false
	for _, resource := range page.Resources {
		if resource.ID == f.userA.Id {
			sawOwnUser = true
		}
	}
	if !sawOwnUser {
		t.Fatalf("same-tenant user %q missing from org-scoped SCIM GetAll results", f.userA.Id)
	}

	// The unrestricted built-in global admin must still see users from both
	// organizations.
	globalPage, err := h.GetAll(requestAsOwner(""), elimityscim.ListRequestParams{Count: 1000, StartIndex: 1})
	if err != nil {
		t.Fatalf("global admin SCIM GetAll unexpectedly failed: %v", err)
	}
	sawA, sawB := false, false
	for _, resource := range globalPage.Resources {
		if resource.ID == f.userA.Id {
			sawA = true
		}
		if resource.ID == f.userB.Id {
			sawB = true
		}
	}
	if !sawA || !sawB {
		t.Fatalf("global admin SCIM GetAll should see both tenants' users: sawA=%v sawB=%v", sawA, sawB)
	}
}

func TestUserResourceHandlerReplaceEnforcesOrgScope(t *testing.T) {
	f := setupScimOrgScopeFixture(t)
	h := UserResourceHandler{}

	attackAttrs := elimityscim.ResourceAttributes{
		"userName":    f.userB.Name,
		"displayName": "PWNED-BY-ORGA-ADMIN",
		UserExtensionKey: map[string]interface{}{
			"organization": f.userB.Owner,
		},
	}

	// An org-scoped admin of orgA must be denied when replacing a user that
	// belongs to orgB, and the write must not be applied.
	_, err := h.Replace(requestAsOwner(f.orgA.Name), f.userB.Id, attackAttrs)
	if err == nil {
		t.Fatalf("VIOLATION: org-scoped admin of %q was able to modify cross-tenant user %q via SCIM Replace", f.orgA.Name, f.userB.Id)
	}
	if !isScimNotFound(err) {
		t.Fatalf("expected a 404 ScimError for cross-tenant Replace, got: %v", err)
	}
	reloaded, loadErr := object.GetUserByUserIdOnly(f.userB.Id)
	if loadErr != nil {
		t.Fatalf("failed to reload victim user: %v", loadErr)
	}
	if reloaded.DisplayName == "PWNED-BY-ORGA-ADMIN" {
		t.Fatalf("VIOLATION: cross-tenant SCIM Replace was persisted despite the denial")
	}

	// Positive control: the same admin replacing a user in their own org
	// must still succeed.
	ownAttrs := elimityscim.ResourceAttributes{
		"userName":    f.userA.Name,
		"displayName": "Updated By Own Org Admin",
		UserExtensionKey: map[string]interface{}{
			"organization": f.userA.Owner,
		},
	}
	if _, err := h.Replace(requestAsOwner(f.orgA.Name), f.userA.Id, ownAttrs); err != nil {
		t.Fatalf("same-tenant SCIM Replace unexpectedly failed: %v", err)
	}
}

func TestUserResourceHandlerDeleteEnforcesOrgScope(t *testing.T) {
	f := setupScimOrgScopeFixture(t)
	h := UserResourceHandler{}

	err := h.Delete(requestAsOwner(f.orgA.Name), f.userB.Id)
	if err == nil {
		t.Fatalf("VIOLATION: org-scoped admin of %q was able to delete cross-tenant user %q via SCIM Delete", f.orgA.Name, f.userB.Id)
	}
	if !isScimNotFound(err) {
		t.Fatalf("expected a 404 ScimError for cross-tenant Delete, got: %v", err)
	}
	reloaded, loadErr := object.GetUserByUserIdOnly(f.userB.Id)
	if loadErr != nil {
		t.Fatalf("failed to reload victim user: %v", loadErr)
	}
	if reloaded == nil {
		t.Fatalf("VIOLATION: cross-tenant SCIM Delete removed the victim user despite the denial")
	}
}
