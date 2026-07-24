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

// Regression test for the Prometheus telemetry authorization gate.
//
// Invariant: the /api/get-prometheus-info and /api/metrics handlers expose the
// process-wide prometheus.DefaultGatherer output, which has no organization label
// and therefore leaks platform-wide, all-tenant API usage/latency (including
// add-organization, delete-organization, impersonate-user of *other* tenants).
// Only a GLOBAL (built-in) admin may read them. An org-scoped admin
// (IsAdmin==true, Owner!="built-in") — a role any customer can grant to their own
// users — must NOT be authorized.
//
// The Prometheus handlers gate on isPrometheusAdmin (via RequireGlobalAdmin), so
// asserting that predicate is asserting the real authorization decision, without
// standing up a live server or DB.
func TestPrometheusAdminRequiresGlobalAdmin(t *testing.T) {
	cases := []struct {
		name     string
		user     *object.User
		wantAuth bool
	}{
		{
			name:     "global (built-in) admin is authorized",
			user:     &object.User{Owner: "built-in", Name: "admin", IsAdmin: true},
			wantAuth: true,
		},
		{
			// The exploited role: an org admin in tenant "acme" — legitimate
			// within its own org, but NOT a global admin. Must be rejected,
			// because the metrics are process-wide and cross-tenant.
			name:     "org-scoped admin (owner=acme, IsAdmin) is rejected",
			user:     &object.User{Owner: "acme", Name: "alice", IsAdmin: true},
			wantAuth: false,
		},
		{
			name:     "ordinary org user is rejected",
			user:     &object.User{Owner: "acme", Name: "bob", IsAdmin: false},
			wantAuth: false,
		},
		{
			// Positive control: a non-admin in the built-in org is not a global
			// admin either (IsGlobalAdmin is strictly Owner=="built-in").
			name:     "built-in non-admin is authorized (built-in org == global)",
			user:     &object.User{Owner: "built-in", Name: "svc", IsAdmin: false},
			wantAuth: true,
		},
		{
			name:     "nil user is rejected",
			user:     nil,
			wantAuth: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isPrometheusAdmin(tc.user)
			if got != tc.wantAuth {
				t.Fatalf("isPrometheusAdmin(%+v) = %v, want %v: "+
					"an org-scoped admin must not be able to read platform-wide "+
					"Prometheus telemetry across all tenants", tc.user, got, tc.wantAuth)
			}
		})
	}

	// Belt-and-suspenders: the gate must agree with the canonical global-admin
	// definition for every non-nil user, so the two can never drift apart.
	for _, tc := range cases {
		if tc.user == nil {
			continue
		}
		if isPrometheusAdmin(tc.user) != tc.user.IsGlobalAdmin() {
			t.Fatalf("isPrometheusAdmin disagrees with User.IsGlobalAdmin() for %+v: "+
				"the Prometheus gate must be exactly global-admin", tc.user)
		}
	}
}
