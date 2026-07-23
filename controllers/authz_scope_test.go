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

import "testing"

// TestCanReadTenantScope asserts the tenant-scoping invariant that guards the
// tenant-scoped read endpoints (GET /api/get-resources and
// GET /api/get-all-objects / -actions / -roles):
//
//	A caller must not read data scoped to another organization's owner unless it
//	is a global admin; an anonymous caller must not read any tenant's scope.
//
// This is the invariant violated by TC-578D05FB (cross-tenant resource listing
// via the `owner` param) and TC-925D23C4 (unauthenticated / cross-tenant
// enumeration of a user's granted objects/actions/roles via the `userId`
// param). Both bugs stem from the handlers passing the client-supplied owner /
// userId straight through with no comparison to the caller's identity.
//
// Each case pairs a legitimate (green) request with the attacking (red)
// request so a failure is provably the missing authorization check, not a
// broken setup.
func TestCanReadTenantScope(t *testing.T) {
	const orgAlpha = "org-alpha"
	const orgBeta = "org-beta"

	cases := []struct {
		name                string
		callerOwner         string
		callerIsGlobalAdmin bool
		requestedOwner      string
		want                bool
	}{
		// --- Positive controls: legitimate reads that must stay allowed. ---
		{
			name:           "same-org caller reads its own org (self-service)",
			callerOwner:    orgAlpha,
			requestedOwner: orgAlpha,
			want:           true,
		},
		{
			name:                "global admin reads any org",
			callerOwner:         "built-in",
			callerIsGlobalAdmin: true,
			requestedOwner:      orgBeta,
			want:                true,
		},

		// --- Attacks: cross-tenant / anonymous reads that must be refused. ---
		{
			// TC-578D05FB: org-alpha admin lists org-beta's resources by owner.
			// TC-925D23C4: org-alpha admin reads org-beta user's grants.
			name:           "cross-tenant caller reads another org (must be denied)",
			callerOwner:    orgAlpha,
			requestedOwner: orgBeta,
			want:           false,
		},
		{
			// TC-925D23C4: fully unauthenticated visitor supplies a victim owner.
			name:           "anonymous caller reads a tenant (must be denied)",
			callerOwner:    "",
			requestedOwner: orgBeta,
			want:           false,
		},
		{
			// A non-global-admin must not read across orgs even if it supplies
			// its own org as caller but points at a foreign owner.
			name:           "non-admin caller cannot escalate to a foreign owner",
			callerOwner:    orgBeta,
			requestedOwner: orgAlpha,
			want:           false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canReadTenantScope(tc.callerOwner, tc.callerIsGlobalAdmin, tc.requestedOwner)
			if got != tc.want {
				t.Fatalf("canReadTenantScope(callerOwner=%q, globalAdmin=%v, requestedOwner=%q) = %v, want %v",
					tc.callerOwner, tc.callerIsGlobalAdmin, tc.requestedOwner, got, tc.want)
			}
		})
	}
}
