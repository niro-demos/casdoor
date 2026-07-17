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

package scim

// Regression coverage for: an organization-scoped SCIM admin (IsAdmin=true,
// Owner != "built-in") must not be able to read, list, or modify user
// accounts belonging to a DIFFERENT organization -- including resetting
// their password or moving them between organizations -- through the
// directory-provisioning API (/scim/Users). controllers.HandleScim used to
// discard the caller's own organization (`_, ok := c.RequireAdmin()`)
// before dispatching into these resource handlers, so every handler below
// operated with no org filter at all.
//
// These tests exercise the scim.UserResourceHandler methods directly
// (bypassing HTTP/session plumbing, which controllers.HandleScim already
// covers) against the project's real object/user.go + a real database, the
// same way object package tests in this repo do (see e.g.
// object/transaction_test.go). The caller's organization boundary is
// attached to the request the same way controllers.HandleScim attaches it
// in production: via WithCallerOwner.

import (
	"net/http"
	"testing"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	scimlib "github.com/elimity-com/scim"
	filter "github.com/scim2/filter-parser/v2"
)

// requestScopedAs builds a SCIM request carrying the caller-organization
// scope the way controllers.HandleScim attaches it after RequireAdmin():
// owner == "" means an unrestricted (global) admin, any other value confines
// the caller to that single organization.
func requestScopedAs(t *testing.T, owner string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/Users", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	return WithCallerOwner(req, owner)
}

func mustPath(t *testing.T, raw string) *filter.Path {
	t.Helper()
	p, err := filter.ParsePath([]byte(raw))
	if err != nil {
		t.Fatalf("parsing SCIM path %q: %v", raw, err)
	}
	return &p
}

// seedCrossOrgFixture creates two isolated organizations (each with the one
// application AddUser requires), and one user in each, using the project's
// own object.Add* creation path -- not raw SQL -- and registers cleanup so
// the shared test database is left as it found it.
func seedCrossOrgFixture(t *testing.T) (userA *object.User, userB *object.User) {
	t.Helper()
	object.InitConfig()
	object.InitDb()
	// InitDb() only wires up the process-local user/group enforcer
	// (userEnforcer) when the built-in Casbin model doesn't already exist in
	// the database -- which it does on this shared, already-bootstrapped
	// test database. InitUserManager() sets it unconditionally, which
	// DeleteUser() (used by this fixture's cleanup) needs.
	object.InitUserManager()

	suffix := util.GenerateId()

	mkOrgAndApp := func(org string) {
		organization := &object.Organization{
			Owner:        "admin",
			Name:         org,
			DisplayName:  org,
			CreatedTime:  util.GetCurrentTime(),
			PasswordType: "plain",
		}
		ok, err := object.AddOrganization(organization)
		if err != nil || !ok {
			t.Fatalf("seed organization %s: ok=%v err=%v", org, ok, err)
		}
		t.Cleanup(func() {
			_, _ = object.DeleteOrganization(&object.Organization{Owner: "admin", Name: org})
		})

		application := &object.Application{
			Owner:        "admin",
			Name:         "app-" + org,
			DisplayName:  "app-" + org,
			Organization: org,
			CreatedTime:  util.GetCurrentTime(),
		}
		ok, err = object.AddApplication(application)
		if err != nil || !ok {
			t.Fatalf("seed application for %s: ok=%v err=%v", org, ok, err)
		}
		t.Cleanup(func() {
			_, _ = object.DeleteApplication(application)
		})
	}

	orgA := "niro-scim-test-org-a-" + suffix
	orgB := "niro-scim-test-org-b-" + suffix
	mkOrgAndApp(orgA)
	mkOrgAndApp(orgB)

	mkUser := func(org, name string) *object.User {
		u := &object.User{
			Owner:       org,
			Name:        name,
			CreatedTime: util.GetCurrentTime(),
			DisplayName: name,
			Email:       name + "@example.com",
			Password:    "Original-Test-Pw1!",
		}
		ok, err := object.AddUser(u, "en")
		if err != nil || !ok {
			t.Fatalf("seed user %s/%s: ok=%v err=%v", org, name, ok, err)
		}
		t.Cleanup(func() { _, _ = object.DeleteUser(u) })
		return u
	}

	userA = mkUser(orgA, "user-a")
	userB = mkUser(orgB, "user-b")
	return userA, userB
}

func TestUserResourceHandlerGetDeniesCrossOrgRead(t *testing.T) {
	userA, userB := seedCrossOrgFixture(t)
	h := UserResourceHandler{}

	// Positive control (must stay green): an org-scoped admin can read
	// their OWN organization's user record. Proves the handler/session
	// path itself works, isolating the failure below to the org boundary.
	res, err := h.Get(requestScopedAs(t, userA.Owner), userA.Id)
	if err != nil {
		t.Fatalf("positive control broke: in-org Get failed (%v) -- endpoint itself is broken, not just the org boundary", err)
	}
	if res.ID != userA.Id {
		t.Fatalf("positive control broke: in-org Get returned wrong resource: got %s want %s", res.ID, userA.Id)
	}

	// Violation under test: the SAME org-scoped admin must be denied when
	// reading a user that belongs to a DIFFERENT organization.
	_, err = h.Get(requestScopedAs(t, userA.Owner), userB.Id)
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin (owner=%q) was able to read a user (owner=%q) belonging to a different organization via SCIM GET /Users/%s", userA.Owner, userB.Owner, userB.Id)
	}

	// A true global admin (owner == "", i.e. Owner == "built-in" per
	// RequireAdmin) is not confined to a single organization.
	res, err = h.Get(requestScopedAs(t, ""), userB.Id)
	if err != nil {
		t.Fatalf("global admin Get of an any-org user should succeed: %v", err)
	}
	if res.ID != userB.Id {
		t.Fatalf("global admin Get returned wrong resource: got %s want %s", res.ID, userB.Id)
	}
}

func TestUserResourceHandlerGetAllScopesToCallerOrg(t *testing.T) {
	userA, userB := seedCrossOrgFixture(t)
	h := UserResourceHandler{}

	page, err := h.GetAll(requestScopedAs(t, userA.Owner), scimlib.ListRequestParams{StartIndex: 1, Count: 100})
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}

	sawOwnOrgUser := false
	for _, res := range page.Resources {
		if res.ID == userB.Id {
			t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin (owner=%q) listing via SCIM GET /Users included a user (owner=%q) from a DIFFERENT organization", userA.Owner, userB.Owner)
		}
		if res.ID == userA.Id {
			sawOwnOrgUser = true
		}
	}
	if !sawOwnOrgUser {
		t.Fatalf("positive control broke: org-scoped admin's listing did not include their OWN organization's user -- endpoint itself is broken, not just the boundary")
	}
}

func TestUserResourceHandlerPatchEnforcesOrgBoundary(t *testing.T) {
	userA, userB := seedCrossOrgFixture(t)
	h := UserResourceHandler{}

	// Violation under test: an org-scoped admin must not be able to modify
	// -- e.g. reset the password of -- a user in a DIFFERENT organization.
	_, err := h.Patch(requestScopedAs(t, userA.Owner), userB.Id, []scimlib.PatchOperation{
		{Op: scimlib.PatchOperationReplace, Path: mustPath(t, "password"), Value: "PWNED-Test-Pw1!"},
	})
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin (owner=%q) was able to PATCH (password reset) a user (owner=%q) belonging to a different organization via SCIM", userA.Owner, userB.Owner)
	}
	reloaded, rerr := object.GetUserByUserIdOnly(userB.Id)
	if rerr != nil {
		t.Fatalf("reloading userB: %v", rerr)
	}
	if reloaded.Password != userB.Password {
		t.Fatalf("SECURITY INVARIANT VIOLATED: cross-org PATCH silently changed userB's password despite the denial")
	}

	// Positive control: an org-scoped admin can patch their OWN
	// organization's user.
	_, err = h.Patch(requestScopedAs(t, userA.Owner), userA.Id, []scimlib.PatchOperation{
		{Op: scimlib.PatchOperationReplace, Path: mustPath(t, "displayName"), Value: "Updated By Org Admin"},
	})
	if err != nil {
		t.Fatalf("positive control broke: in-org Patch failed (%v) -- endpoint itself is broken, not just the boundary", err)
	}

	// Extension of the same primitive (called out in the finding): an
	// org-scoped admin must not be able to move their OWN organization's
	// user into a DIFFERENT organization via the SCIM enterprise-user
	// "organization" extension field.
	_, err = h.Patch(requestScopedAs(t, userA.Owner), userA.Id, []scimlib.PatchOperation{
		{Op: scimlib.PatchOperationReplace, Path: mustPath(t, UserExtensionKey+".organization"), Value: userB.Owner},
	})
	if err != nil {
		t.Fatalf("org-reassignment patch itself should not error (it must be silently clamped to the caller's own org): %v", err)
	}
	reloaded, rerr = object.GetUserByUserIdOnly(userA.Id)
	if rerr != nil {
		t.Fatalf("reloading userA: %v", rerr)
	}
	if reloaded.Owner != userA.Owner {
		t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin reassigned their own user's organization from %q to %q via SCIM PATCH", userA.Owner, reloaded.Owner)
	}
}
