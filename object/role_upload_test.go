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

// Same invariant as the permission-upload path (role_upload.go shares the root
// cause): an org-scoped admin bulk-uploading roles must not create Role records
// owned by another organization, nor name subjects outside their own org.
func TestScopeUploadedRolesToOwner(t *testing.T) {
	const owner = "org-alpha"

	rows := []*Role{
		{Owner: "org-alpha", Name: "own-role", IsEnabled: true},
		{Owner: "built-in", Name: "evil-builtin", IsEnabled: true},
		{Owner: "org-beta", Name: "evil-beta", IsEnabled: true},
		{Owner: "org-alpha", Name: "cross-subject", Users: []string{"org-beta/victim"}, Roles: []string{"org-beta/admins"}, Groups: []string{"org-gamma/g1"}},
	}

	got := scopeUploadedRolesToOwner(owner, rows)

	for _, r := range got {
		if r.Owner != owner {
			t.Fatalf("INVARIANT VIOLATED: role upload as %q produced a row owned by %q (name=%q) — a cross-tenant role plant", owner, r.Owner, r.Name)
		}
	}

	if findRole(got, "own-role") == nil {
		t.Fatalf("legitimate own-org role (own-role) was dropped; scoping must keep in-org rows")
	}

	if r := findRole(got, "cross-subject"); r != nil {
		assertNoForeignSubject(t, owner, "users", r.Users)
		assertNoForeignSubject(t, owner, "roles", r.Roles)
		assertNoForeignSubject(t, owner, "groups", r.Groups)
	}
}

func TestScopeUploadedRolesToOwner_GlobalAdminUnrestricted(t *testing.T) {
	rows := []*Role{
		{Owner: "org-alpha", Name: "r1"},
		{Owner: "org-beta", Name: "r2"},
	}

	got := scopeUploadedRolesToOwner("built-in", rows)

	if len(got) != 2 {
		t.Fatalf("global admin role upload dropped rows: got %d, want 2", len(got))
	}
	if findRole(got, "r1").Owner != "org-alpha" || findRole(got, "r2").Owner != "org-beta" {
		t.Fatalf("global admin role owners were clobbered: %+v", got)
	}
}

func findRole(rs []*Role, name string) *Role {
	for _, r := range rs {
		if r.Name == name {
			return r
		}
	}
	return nil
}
