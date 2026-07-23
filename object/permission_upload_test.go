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

import "testing"

// Invariant: an org-scoped admin uploading a spreadsheet of permissions must not
// be able to create Permission records owned by a different organization, nor
// name subjects (users/roles/groups) outside their own organization.
//
// The upload's `owner` argument is the caller's enforced session org
// (controllers/permission_upload.go derives it from the session). The parsed
// rows' Owner/Users/Roles/Groups fields come verbatim from the uploaded file and
// must be re-scoped to that owner before persistence.
func TestScopeUploadedPermissionsToOwner(t *testing.T) {
	// Caller is admin of org-alpha only (NOT a global admin).
	const owner = "org-alpha"

	rows := []*Permission{
		// legitimate own-org row — must survive, unchanged
		{Owner: "org-alpha", Name: "own-perm", Resources: []string{"*"}, Actions: []string{"*"}, Effect: "Allow", IsEnabled: true},
		// attack: row claims owner="built-in" (Casdoor's global-admin org)
		{Owner: "built-in", Name: "evil-builtin", Resources: []string{"*"}, Actions: []string{"*"}, Effect: "Allow", IsEnabled: true},
		// attack: row claims owner="org-beta", a tenant the caller does not administer
		{Owner: "org-beta", Name: "evil-beta", Resources: []string{"*"}, Actions: []string{"*"}, Effect: "Allow", IsEnabled: true},
		// attack: own-org row that plants a cross-org subject reference
		{Owner: "org-alpha", Name: "cross-subject", Users: []string{"org-beta/victim"}, Roles: []string{"org-beta/admins"}, Groups: []string{"org-gamma/g1"}},
	}

	got := scopeUploadedPermissionsToOwner(owner, rows)

	// INVARIANT 1: no surviving row may be owned by an org other than the caller's.
	for _, p := range got {
		if p.Owner != owner {
			t.Fatalf("INVARIANT VIOLATED: upload as %q produced a row owned by %q (name=%q) — a cross-tenant permission plant", owner, p.Owner, p.Name)
		}
	}

	// INVARIANT 2: the caller's own-org name/authority is preserved, not silently
	// dropped — so a legitimate self-scoped upload still works.
	if findPermission(got, "own-perm") == nil {
		t.Fatalf("legitimate own-org row (own-perm) was dropped; scoping must keep in-org rows")
	}

	// INVARIANT 3: subject references (users/roles/groups) outside the caller's org
	// must not be planted. The row itself may be kept (rescoped to owner), but no
	// foreign-org subject may survive on it.
	if p := findPermission(got, "cross-subject"); p != nil {
		assertNoForeignSubject(t, owner, "users", p.Users)
		assertNoForeignSubject(t, owner, "roles", p.Roles)
		assertNoForeignSubject(t, owner, "groups", p.Groups)
	}
}

// A global admin (owner == "built-in") legitimately owns records in any org, so
// scoping must NOT clobber their explicitly-set owners.
func TestScopeUploadedPermissionsToOwner_GlobalAdminUnrestricted(t *testing.T) {
	rows := []*Permission{
		{Owner: "org-alpha", Name: "p1"},
		{Owner: "org-beta", Name: "p2"},
	}

	got := scopeUploadedPermissionsToOwner("built-in", rows)

	if len(got) != 2 {
		t.Fatalf("global admin upload dropped rows: got %d, want 2", len(got))
	}
	if findPermission(got, "p1").Owner != "org-alpha" || findPermission(got, "p2").Owner != "org-beta" {
		t.Fatalf("global admin owners were clobbered: %+v", got)
	}
}

func findPermission(ps []*Permission, name string) *Permission {
	for _, p := range ps {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func assertNoForeignSubject(t *testing.T, owner, field string, refs []string) {
	t.Helper()
	for _, ref := range refs {
		refOwner, _ := splitSubjectOwner(ref)
		if refOwner != "" && refOwner != owner {
			t.Fatalf("INVARIANT VIOLATED: upload as %q kept foreign %s subject %q (owner %q)", owner, field, ref, refOwner)
		}
	}
}

// splitSubjectOwner extracts the org prefix of an "org/name" subject reference.
func splitSubjectOwner(ref string) (string, string) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == '/' {
			return ref[:i], ref[i+1:]
		}
	}
	return "", ref
}
