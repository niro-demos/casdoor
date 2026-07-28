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

package object

import (
	"testing"
)

// TestCheckPermissionForUpdateUserRevertsEmailVerified is the regression
// test for TC-EAC1F64F: CheckPermissionForUpdateUser is the sole
// authorization/reversion checkpoint POST /api/update-user runs every
// incoming field through, and it has explicit revert-if-unauthorized
// branches for every other sensitive field (Email, Phone, IsAdmin,
// IsForbidden, ...) but had none at all for EmailVerified. That let a
// standard, non-admin caller flip her own emailVerified flag to true in the
// same request body, with no verification-code/OTP challenge ever
// completed, by calling POST /api/update-user?columns=emailVerified with
// {"emailVerified":true}.
//
// Invariant under test: a non-admin caller must never be able to set
// EmailVerified via CheckPermissionForUpdateUser; the field must be
// reverted to the existing value unless the caller is an org/global admin
// (mirroring how IsAdmin/IsForbidden/IsDeleted are already gated).
func TestCheckPermissionForUpdateUserRevertsEmailVerified(t *testing.T) {
	InitConfig()
	// DeleteUser (used in cleanup below) touches the package-level
	// user/group enforcer; initialize it so cleanup doesn't panic on a nil
	// enforcer, mirroring how other object-package tests that seed/delete
	// users via AddUsers/DeleteUser set this up.
	InitUserManager()

	userName := "tceac1f64f-alice"
	existing, err := GetUser("built-in/" + userName)
	if err != nil {
		t.Fatalf("failed to check for existing test user: %v", err)
	}
	if existing == nil {
		seedUser := &User{
			Owner:         "built-in",
			Name:          userName,
			Id:            "tceac1f64f-alice-id",
			EmailVerified: false,
		}
		affected, err := AddUsers([]*User{seedUser})
		if err != nil || !affected {
			t.Fatalf("failed to seed test user: affected=%v err=%v", affected, err)
		}
	}
	t.Cleanup(func() {
		if u, _ := GetUser("built-in/" + userName); u != nil {
			_, _ = DeleteUser(u)
		}
	})

	oldUser, err := GetUser("built-in/" + userName)
	if err != nil {
		t.Fatalf("failed to load seeded user: %v", err)
	}
	if oldUser == nil {
		t.Fatalf("seeded user not found")
	}
	if oldUser.EmailVerified {
		t.Fatalf("baseline broken: seeded user unexpectedly has EmailVerified=true")
	}

	// --- Vulnerable case: a standard (non-admin) caller flips her own
	// emailVerified flag with no verification-code challenge ever
	// completed, exactly what POST /api/update-user?columns=emailVerified
	// with {"emailVerified":true} does. ---
	attacker := *oldUser
	attacker.EmailVerified = true

	pass, errMsg := CheckPermissionForUpdateUser(oldUser, &attacker, false, false, "en")
	if !pass {
		t.Fatalf("unexpected rejection unrelated to emailVerified: %s", errMsg)
	}
	if attacker.EmailVerified {
		t.Fatalf("VULNERABLE: non-admin caller was able to set EmailVerified=true via CheckPermissionForUpdateUser; want it reverted to %v", oldUser.EmailVerified)
	}

	// --- Control: a legitimate admin-driven change (mirroring the actual
	// verification-code success path or a deliberate admin action) must
	// still be able to mark the flag verified, so the fix doesn't break the
	// real verification/admin flows. ---
	adminChange := *oldUser
	adminChange.EmailVerified = true
	pass, errMsg = CheckPermissionForUpdateUser(oldUser, &adminChange, true, false, "en")
	if !pass {
		t.Fatalf("admin-driven emailVerified update was unexpectedly rejected: %s", errMsg)
	}
	if !adminChange.EmailVerified {
		t.Fatalf("admin caller should be able to set EmailVerified=true, but it was reverted")
	}

	// --- Control: a legitimate, unrelated self-service field update (no
	// emailVerified change) must still pass through unaffected. ---
	legit := *oldUser
	legit.DisplayName = "Updated Display Name"
	pass, errMsg = CheckPermissionForUpdateUser(oldUser, &legit, false, false, "en")
	if !pass {
		t.Fatalf("unrelated legitimate self-service update was unexpectedly rejected: %s", errMsg)
	}
	if legit.DisplayName != "Updated Display Name" {
		t.Fatalf("unrelated legitimate field change should not be reverted, got %q", legit.DisplayName)
	}
}
