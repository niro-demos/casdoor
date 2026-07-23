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

// TestEnforcerModelAdapterOwnership asserts the security invariant that an
// enforcer created/updated by a non-global admin may only reference a model and
// adapter owned by the enforcer's own organization. Referencing another org's
// (especially the platform "built-in") model/adapter is what lets an org-scoped
// admin wrap and read/overwrite the site-wide authorization policy table.
//
// The check must be relaxed only for a verified global admin, who legitimately
// manages the platform-shared built-in objects.
func TestEnforcerModelAdapterOwnership(t *testing.T) {
	cases := []struct {
		name          string
		enforcer      *Enforcer
		isGlobalAdmin bool
		wantErr       bool
	}{
		{
			name: "same-org model and adapter is allowed",
			enforcer: &Enforcer{
				Owner:   "org-alpha",
				Name:    "e1",
				Model:   "org-alpha/model-1",
				Adapter: "org-alpha/adapter-1",
			},
			isGlobalAdmin: false,
			wantErr:       false,
		},
		{
			// The exploit: org-scoped enforcer wired to the global built-in
			// model/adapter, which back the site-wide policy table.
			name: "cross-org built-in adapter is rejected for org admin",
			enforcer: &Enforcer{
				Owner:   "org-alpha",
				Name:    "alpha-enforcer-crossref",
				Model:   "built-in/api-model-built-in",
				Adapter: "built-in/api-adapter-built-in",
			},
			isGlobalAdmin: false,
			wantErr:       true,
		},
		{
			// Even if only one of the two references crosses the org boundary
			// the enforcer must be rejected.
			name: "cross-org adapter only is rejected for org admin",
			enforcer: &Enforcer{
				Owner:   "org-alpha",
				Name:    "e2",
				Model:   "org-alpha/model-1",
				Adapter: "built-in/api-adapter-built-in",
			},
			isGlobalAdmin: false,
			wantErr:       true,
		},
		{
			name: "cross-org model only is rejected for org admin",
			enforcer: &Enforcer{
				Owner:   "org-alpha",
				Name:    "e3",
				Model:   "org-beta/model-9",
				Adapter: "org-alpha/adapter-1",
			},
			isGlobalAdmin: false,
			wantErr:       true,
		},
		{
			// A global admin legitimately manages the platform-shared built-in
			// model/adapter, so the same wiring is allowed for them.
			name: "cross-org built-in is allowed for a verified global admin",
			enforcer: &Enforcer{
				Owner:   "built-in",
				Name:    "api-enforcer-built-in",
				Model:   "built-in/api-model-built-in",
				Adapter: "built-in/api-adapter-built-in",
			},
			isGlobalAdmin: true,
			wantErr:       false,
		},
		{
			// Empty model/adapter is handled elsewhere (InitEnforcer); the
			// ownership gate must not spuriously reject them.
			name: "empty model and adapter is not rejected by the ownership gate",
			enforcer: &Enforcer{
				Owner: "org-alpha",
				Name:  "e4",
			},
			isGlobalAdmin: false,
			wantErr:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckEnforcerModelAdapterOwnership(tc.enforcer, tc.isGlobalAdmin)
			if tc.wantErr && err == nil {
				t.Fatalf("expected ownership violation to be rejected, got nil error for enforcer %s referencing model=%q adapter=%q (isGlobalAdmin=%v)",
					tc.enforcer.GetId(), tc.enforcer.Model, tc.enforcer.Adapter, tc.isGlobalAdmin)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected legitimate enforcer to be allowed, got error: %v", err)
			}
		})
	}
}
