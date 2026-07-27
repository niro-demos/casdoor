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

func TestValidateDcrRedirectUrisRejectsUnsafeSchemes(t *testing.T) {
	tests := []struct {
		name         string
		redirectUris []string
		wantError    bool
	}{
		{
			name:         "https web redirect",
			redirectUris: []string{"https://client.example.com/callback"},
		},
		{
			name:         "javascript redirect",
			redirectUris: []string{"javascript:alert(97)"},
			wantError:    true,
		},
		{
			name:         "data redirect",
			redirectUris: []string{"data:text/html,alert(97)"},
			wantError:    true,
		},
		{
			name:         "file redirect",
			redirectUris: []string{"file:///tmp/callback"},
			wantError:    true,
		},
		{
			name:         "http web redirect",
			redirectUris: []string{"http://client.example.com/callback"},
			wantError:    true,
		},
		{
			name:         "relative redirect",
			redirectUris: []string{"/callback"},
			wantError:    true,
		},
		{
			name:         "hostless https redirect",
			redirectUris: []string{"https:///callback"},
			wantError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errResp := validateDcrRedirectUris(tt.redirectUris)
			if tt.wantError {
				if errResp == nil {
					t.Fatalf("validateDcrRedirectUris(%v) returned nil, want invalid_redirect_uri", tt.redirectUris)
				}
				if errResp.Error != "invalid_redirect_uri" {
					t.Fatalf("validateDcrRedirectUris(%v) error = %q, want invalid_redirect_uri", tt.redirectUris, errResp.Error)
				}
				return
			}

			if errResp != nil {
				t.Fatalf("validateDcrRedirectUris(%v) returned %q, want nil", tt.redirectUris, errResp.Error)
			}
		})
	}
}
