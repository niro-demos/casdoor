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

	"github.com/casdoor/casdoor/util"
)

// TestDeleteOrganizationRequiresGlobalAdmin guards the invariant behind
// TC-D7FC7779: an organization-scoped admin (IsAdmin == true but Owner !=
// "built-in", so IsGlobalAdmin() is false) must not be able to permanently
// delete their own organization. Deleting an organization is an
// instance-wide destructive operation and, like AddOrganization, must be
// reserved for a global/instance admin - otherwise any org-scoped admin can
// lock every user of their tenant out of authentication with one API call.
func TestDeleteOrganizationRequiresGlobalAdmin(t *testing.T) {
	InitConfig()

	orgName := "niro-verify-delorg-" + util.GenerateTimeId()
	org := &Organization{
		Owner:       "admin",
		Name:        orgName,
		DisplayName: "Niro Verify Delete-Org Test",
	}

	affected, err := AddOrganization(org)
	if err != nil {
		t.Fatalf("setup: could not create test organization: %v", err)
	}
	if !affected {
		t.Fatalf("setup: AddOrganization reported no rows affected for %s", orgName)
	}
	// Belt-and-braces cleanup: if the test fails after the org-scoped-admin
	// deletion is (wrongly) allowed, orgExistsAfterAttack below already
	// reflects that; this defer removes the row in either outcome so the
	// shared test database is left clean.
	defer func() {
		_, _ = deleteOrganization(&Organization{Owner: "admin", Name: orgName})
	}()

	// THE ACTUAL TEST — an org-scoped (non-global) admin attempts to delete
	// their own organization. This must be denied: no rows may be removed,
	// and an error must be returned.
	orgScopedAdminAffected, err := DeleteOrganization(&Organization{Owner: "admin", Name: orgName}, false, "en")
	if err == nil {
		t.Fatalf("org-scoped admin (isGlobalAdmin=false) deleted organization %q without error; expected an authorization error", orgName)
	}
	if orgScopedAdminAffected {
		t.Fatalf("org-scoped admin (isGlobalAdmin=false) reported affected=true deleting organization %q; expected the delete to be rejected", orgName)
	}

	// Verify the organization row is still present — the denial must be
	// real, not just an error return with the row removed anyway.
	stillExists, err := getOrganization("admin", orgName)
	if err != nil {
		t.Fatalf("could not verify organization %q survived the denied delete: %v", orgName, err)
	}
	if stillExists == nil {
		t.Fatalf("organization %q was removed even though DeleteOrganization returned an authorization error — tenant would be locked out", orgName)
	}

	// Control — the same request, performed by a global admin
	// (isGlobalAdmin=true), must succeed. This proves the denial above is
	// specific to the missing global-admin privilege, not a broken
	// environment or an over-broad fix that blocks deletion outright.
	globalAdminAffected, err := DeleteOrganization(&Organization{Owner: "admin", Name: orgName}, true, "en")
	if err != nil {
		t.Fatalf("global admin (isGlobalAdmin=true) could not delete organization %q: %v", orgName, err)
	}
	if !globalAdminAffected {
		t.Fatalf("global admin (isGlobalAdmin=true) delete of organization %q reported no rows affected", orgName)
	}

	goneNow, err := getOrganization("admin", orgName)
	if err != nil {
		t.Fatalf("could not verify organization %q was removed by the global admin: %v", orgName, err)
	}
	if goneNow != nil {
		t.Fatalf("organization %q still exists after a global admin's DeleteOrganization call", orgName)
	}
}

// TestDeleteOrganizationStillProtectsBuiltIn is a narrow regression guard
// for the pre-existing "built-in" name guard in DeleteOrganization: it must
// keep rejecting deletion of the built-in organization even for a caller
// that is a global admin, so the new authorization gate does not loosen
// this existing protection.
func TestDeleteOrganizationStillProtectsBuiltIn(t *testing.T) {
	InitConfig()

	affected, err := DeleteOrganization(&Organization{Owner: "admin", Name: "built-in"}, true, "en")
	if err != nil {
		t.Fatalf("unexpected error deleting built-in organization as global admin: %v", err)
	}
	if affected {
		t.Fatalf("DeleteOrganization reported affected=true for the built-in organization; it must always be protected")
	}
}
