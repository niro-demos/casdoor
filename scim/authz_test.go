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

package scim

import (
	"net/http/httptest"
	"testing"
)

// TestCallerCanAccessOwner_TenantIsolation is the regression test for
// TC-B4C14BF5: the SCIM User API let an org-scoped admin in one tenant read,
// modify, and delete users in ANY other tenant.
//
// Invariant: an admin authenticated to the SCIM API may only act on user
// accounts that belong to their own organization; a global/built-in admin may
// act across all tenants. This test locks down the authorization decision every
// SCIM User handler method now makes before any read or write.
func TestCallerCanAccessOwner_TenantIsolation(t *testing.T) {
	tests := []struct {
		name          string
		callerOwner   string
		resourceOwner string
		want          bool
	}{
		{
			// The exact leak from the finding: an org-alpha admin reaching an
			// org-beta user. This MUST be denied.
			name:          "org-scoped admin denied cross-tenant (the bug)",
			callerOwner:   "org-alpha",
			resourceOwner: "org-beta",
			want:          false,
		},
		{
			// Positive control from the PoC: the same admin acting on its OWN
			// org must still succeed, proving the deny above is the tenant
			// boundary and not a broken environment.
			name:          "org-scoped admin allowed within own tenant (control)",
			callerOwner:   "org-alpha",
			resourceOwner: "org-alpha",
			want:          true,
		},
		{
			// An org admin must not be able to touch the global built-in admin.
			name:          "org-scoped admin denied access to built-in tenant",
			callerOwner:   "org-alpha",
			resourceOwner: "built-in",
			want:          false,
		},
		{
			// Global/built-in admin (empty caller owner) keeps cross-tenant
			// provisioning ability.
			name:          "global admin allowed across any tenant",
			callerOwner:   "",
			resourceOwner: "org-beta",
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := callerCanAccessOwner(tt.callerOwner, tt.resourceOwner); got != tt.want {
				t.Errorf("callerCanAccessOwner(%q, %q) = %v, want %v",
					tt.callerOwner, tt.resourceOwner, got, tt.want)
			}
		})
	}
}

// TestCallerOwnerFromRequest_MissingContextDenies ensures that a request with no
// caller-owner context (e.g. a SCIM handler reached without HandleScim
// populating the tenant) is treated as "no tenant context" and therefore denied
// for an org-scoped decision — never silently promoted to global admin.
func TestCallerOwnerFromRequest_MissingContextDenies(t *testing.T) {
	// No caller owner injected onto the request.
	req := httptest.NewRequest("GET", "/Users", nil)
	owner, ok := callerOwnerFromRequest(req)
	if ok {
		t.Fatalf("expected no caller owner on a bare request, got owner=%q ok=%v", owner, ok)
	}

	// A present, org-scoped caller owner must round-trip through the context.
	req = req.WithContext(WithCallerOwner(req.Context(), "org-alpha"))
	owner, ok = callerOwnerFromRequest(req)
	if !ok || owner != "org-alpha" {
		t.Fatalf("expected caller owner \"org-alpha\", got owner=%q ok=%v", owner, ok)
	}
}
