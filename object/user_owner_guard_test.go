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

package object

import (
	"testing"
)

// TestUpdateUserRejectsMoveToBuiltInOrg is the regression test for
// TC-133B72D8: UpdateUser persisted whatever Owner the caller supplied with
// no check on whether that moved the user into "built-in". Because
// User.IsGlobalAdmin() is defined purely as `Owner == "built-in"`, that move
// is equivalent to silently granting the user global-admin rights over the
// entire instance, regardless of its IsAdmin flag. Both SCIM update
// endpoints (UpdateScimUser, UpdateScimUserByPatchOperation) call this exact
// function with columns=nil, so the default column list (which includes
// "owner") reached the database with no guard, unlike AddUser() which
// already refuses to create a user in "built-in" without the target
// organization's "Has privilege consent" flag.
//
// Invariant under test: a caller must not be able to move an existing user
// into the "built-in" organization via UpdateUser unless the "built-in"
// organization has explicitly opted in via HasPrivilegeConsent (or the
// account is named "admin", mirroring AddUser's exception).
func TestUpdateUserRejectsMoveToBuiltInOrg(t *testing.T) {
	InitConfig()
	// UpdateUser's default column list (used when columns==nil, exactly as
	// the SCIM callers under test do) includes "groups", which touches the
	// package-level user/group enforcer. Initialize it so a real assertion
	// failure isn't masked by an unrelated nil-pointer panic.
	InitUserManager()

	victimOrg := "tc133b72d8-org"
	existingOrg, err := GetOrganization("admin/" + victimOrg)
	if err != nil {
		t.Fatalf("failed to check for existing test organization: %v", err)
	}
	if existingOrg == nil {
		org := &Organization{Owner: "admin", Name: victimOrg}
		affected, err := AddOrganization(org)
		if err != nil || !affected {
			t.Fatalf("failed to seed test organization: affected=%v err=%v", affected, err)
		}
	}

	builtIn, err := GetOrganization("admin/built-in")
	if err != nil {
		t.Fatalf("failed to load built-in organization: %v", err)
	}
	if builtIn == nil {
		t.Fatalf("built-in organization not found in test database")
	}
	if builtIn.HasPrivilegeConsent {
		t.Skip("built-in organization has HasPrivilegeConsent enabled in this environment; the guard under test is conditioned on it being disabled")
	}

	userName := "tc133b72d8-scim-user"
	existingUser, err := GetUser(victimOrg + "/" + userName)
	if err != nil {
		t.Fatalf("failed to check for existing test user: %v", err)
	}
	if existingUser == nil {
		seedUser := &User{
			Owner: victimOrg,
			Name:  userName,
			Id:    victimOrg + "-" + userName + "-tc133b72d8",
		}
		affected, err := AddUsers([]*User{seedUser})
		if err != nil || !affected {
			t.Fatalf("failed to seed test user: affected=%v err=%v", affected, err)
		}
	}

	oldUser, err := GetUser(victimOrg + "/" + userName)
	if err != nil {
		t.Fatalf("failed to load seeded user: %v", err)
	}
	if oldUser == nil {
		t.Fatalf("seeded user not found")
	}

	// --- Vulnerable case: exactly what scim/user_handler.go's
	// UpdateScimUser/UpdateScimUserByPatchOperation do: build a User struct
	// with Owner set to the attacker-chosen organization from the request's
	// enterprise-extension "organization" field, and call UpdateUser with
	// columns=nil, isAdmin=true. ---
	escalated := *oldUser
	escalated.Owner = "built-in"

	affected, err := UpdateUser(oldUser.GetId(), &escalated, nil, true, "en")
	// Registered unconditionally (before inspecting the result) so a
	// vulnerable run that actually relocates the user still cleans it up,
	// rather than leaking state that would corrupt a later test run.
	t.Cleanup(func() {
		if m, _ := GetUser("built-in/" + userName); m != nil {
			_, _ = DeleteUser(m)
		}
	})
	if err == nil {
		t.Fatalf("VULNERABLE: UpdateUser allowed moving user %q into the built-in organization without error (affected=%v)", oldUser.GetId(), affected)
	}

	movedUser, err := GetUser("built-in/" + userName)
	if err != nil {
		t.Fatalf("GetUser for built-in/%s failed: %v", userName, err)
	}
	if movedUser != nil {
		t.Fatalf("VULNERABLE: user row was persisted under owner \"built-in\": %+v", movedUser)
	}

	stillThere, err := GetUser(victimOrg + "/" + userName)
	if err != nil {
		t.Fatalf("GetUser for %s/%s failed: %v", victimOrg, userName, err)
	}
	if stillThere == nil {
		t.Fatalf("user unexpectedly disappeared from its original organization")
	}

	// --- Control: the same caller can still legitimately update the user
	// without changing its owner. Uses an explicit, narrow columns list
	// (rather than columns=nil like the SCIM callers) so this control isn't
	// coupled to the package-level group enforcer, which isn't initialized
	// in this test binary and is unrelated to the guard under test. ---
	legit := *stillThere
	legit.DisplayName = "Updated Display Name"
	if _, err := UpdateUser(legit.GetId(), &legit, []string{"display_name"}, true, "en"); err != nil {
		t.Fatalf("baseline broken: could not update user without changing owner: %v", err)
	}

	updated, err := GetUser(victimOrg + "/" + userName)
	if err != nil {
		t.Fatalf("GetUser after legitimate update failed: %v", err)
	}
	if updated == nil || updated.DisplayName != "Updated Display Name" {
		t.Fatalf("legitimate update did not persist: %+v", updated)
	}
}
