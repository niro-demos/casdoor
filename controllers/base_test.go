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

package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

// TestIsAdminForOrgDecision covers the pure decision behind IsAdminForOrg
// (controllers/base.go), the shared root-cause fix for TC-BAFE51C7: IsAdmin()
// alone returns true for ANY admin, global or org-scoped, without checking
// which organization's data is being requested.
func TestIsAdminForOrgDecision(t *testing.T) {
	orgScopedAdmin := &object.User{Owner: "acme", Name: "acme-admin", IsAdmin: true}
	nonAdmin := &object.User{Owner: "acme", Name: "alice", IsAdmin: false}

	tests := []struct {
		name          string
		isGlobalAdmin bool
		user          *object.User
		owner         string
		want          bool
	}{
		{"global admin may read any org", true, nil, "built-in", true},
		{"global admin may read a different org", true, nil, "acme", true},
		{"org-scoped admin reading their own org is allowed", false, orgScopedAdmin, "acme", true},
		{"org-scoped admin reading another org is denied", false, orgScopedAdmin, "built-in", false},
		{"non-admin user is never treated as org admin", false, nonAdmin, "acme", false},
		{"no session user is denied", false, nil, "acme", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAdminForOrg(tt.isGlobalAdmin, tt.user, tt.owner); got != tt.want {
				t.Errorf("isAdminForOrg(%v, %+v, %q) = %v, want %v", tt.isGlobalAdmin, tt.user, tt.owner, got, tt.want)
			}
		})
	}
}
