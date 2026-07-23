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

// TestIsSignupAllowedForOrganization asserts the signup org-ownership invariant:
// an application may only be used to sign up accounts into the organization that
// actually owns it. An organization that disabled signup on its own application
// must not be reachable through a different, unrelated application that has
// signup enabled while naming that organization in the request body.
func TestIsSignupAllowedForOrganization(t *testing.T) {
	tests := []struct {
		name        string
		application *Application
		targetOrg   string
		want        bool
	}{
		{
			// Legitimate: an org signs up through its own application.
			name:        "own application, matching organization",
			application: &Application{Organization: "org-alpha"},
			targetOrg:   "org-alpha",
			want:        true,
		},
		{
			// The core bug (TC-23A83A2C): the signup-enabled built-in
			// application is used to reach an unrelated organization that
			// disabled signup on its own application. Must be rejected.
			name:        "unrelated application, mismatched organization",
			application: &Application{Organization: "built-in"},
			targetOrg:   "org-alpha",
			want:        false,
		},
		{
			// Shared application addressed as "app-org-<org>": getApplication()
			// sets application.Organization to the shared target org, so a
			// legitimate shared-app signup into that org still matches.
			name:        "shared application resolved to shared organization",
			application: &Application{IsShared: true, Organization: "org-alpha"},
			targetOrg:   "org-alpha",
			want:        true,
		},
		{
			// A shared application must still not be used to sign up into an
			// organization it was not resolved for.
			name:        "shared application, mismatched organization",
			application: &Application{IsShared: true, Organization: "built-in"},
			targetOrg:   "org-alpha",
			want:        false,
		},
		{
			name:        "nil application",
			application: nil,
			targetOrg:   "org-alpha",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSignupAllowedForOrganization(tt.application, tt.targetOrg)
			if got != tt.want {
				t.Errorf("IsSignupAllowedForOrganization(org=%q) = %v, want %v",
					tt.targetOrg, got, tt.want)
			}
		})
	}
}
