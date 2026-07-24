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

// TestCanReadOwnedRecord pins the security invariant behind the billing
// get-by-id endpoints (get-pricing, get-plan, get-subscription):
//
//	A non-admin user in one tenant must not be able to read another tenant's
//	pricing, plan, or subscription record by knowing/guessing the record id.
//
// Before the fix, GetPricing/GetPlan/GetSubscription returned the record with
// no ownership check, so a non-admin cross-tenant caller could read it. The
// cross-tenant cases below are the red ones on the unfixed code; the same-tenant
// and admin cases are the healthy baseline that proves the check is specific and
// does not break legitimate reads.
func TestCanReadOwnedRecord(t *testing.T) {
	cases := []struct {
		name             string
		isAdmin          bool
		sessionUserOwner string
		sessionUserName  string
		recordOwner      string
		recordUser       string // "" for tenant-owned records (pricing, plan)
		want             bool
	}{
		// --- The invariant: cross-tenant non-admin reads are denied ---
		{
			name:             "non-admin cross-tenant pricing/plan read is denied",
			isAdmin:          false,
			sessionUserOwner: "globex", sessionUserName: "carol",
			recordOwner: "acme", recordUser: "",
			want: false,
		},
		{
			name:             "non-admin cross-tenant subscription read is denied",
			isAdmin:          false,
			sessionUserOwner: "globex", sessionUserName: "carol",
			recordOwner: "acme", recordUser: "alice",
			want: false,
		},

		// --- Healthy baseline: legitimate reads still succeed ---
		{
			name:             "non-admin same-tenant tenant-owned read is allowed",
			isAdmin:          false,
			sessionUserOwner: "acme", sessionUserName: "alice",
			recordOwner: "acme", recordUser: "",
			want: true,
		},
		{
			name:             "non-admin reading own subscription is allowed",
			isAdmin:          false,
			sessionUserOwner: "acme", sessionUserName: "alice",
			recordOwner: "acme", recordUser: "alice",
			want: true,
		},

		// --- Subscription discloses a named user: same-tenant, other user denied ---
		{
			name:             "non-admin same-tenant reading another user's subscription is denied",
			isAdmin:          false,
			sessionUserOwner: "acme", sessionUserName: "bob",
			recordOwner: "acme", recordUser: "alice",
			want: false,
		},

		// --- Admins may read anything ---
		{
			name:             "admin cross-tenant read is allowed",
			isAdmin:          true,
			sessionUserOwner: "globex", sessionUserName: "carol",
			recordOwner: "acme", recordUser: "alice",
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanReadOwnedRecord(tc.isAdmin, tc.sessionUserOwner, tc.sessionUserName, tc.recordOwner, tc.recordUser)
			if got != tc.want {
				t.Fatalf("CanReadOwnedRecord(isAdmin=%v, session=%s/%s, record=%s/user=%q) = %v, want %v",
					tc.isAdmin, tc.sessionUserOwner, tc.sessionUserName, tc.recordOwner, tc.recordUser, got, tc.want)
			}
		})
	}
}
