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

// TestIsGlobalAdminDistinguishesOrgAdmin documents the privilege invariant behind
// TC-E5E88ED8 primitive 1 (intranet-scan): the intranet scan surface must be
// gated on global-admin, and an org-scoped admin (IsAdmin=true but owner is a
// tenant org, not "built-in") must NOT count as a global admin. SyncIntranetServers
// is fixed to gate on this predicate instead of on org-level admin.
func TestIsGlobalAdminDistinguishesOrgAdmin(t *testing.T) {
	orgAdmin := &User{Owner: "org-alpha", Name: "alpha-admin", IsAdmin: true}
	if orgAdmin.IsGlobalAdmin() {
		t.Fatalf("org-scoped admin (owner=%q, isAdmin=true) must not be treated as a global admin", orgAdmin.Owner)
	}

	globalAdmin := &User{Owner: "built-in", Name: "admin", IsAdmin: true}
	if !globalAdmin.IsGlobalAdmin() {
		t.Fatalf("built-in admin must be a global admin")
	}
}
