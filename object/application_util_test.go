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

func TestRedirectUriMatchesPattern(t *testing.T) {
	tests := []struct {
		redirectUri string
		targetUri   string
		want        bool
	}{
		// Exact match
		{"https://login.example.com/callback", "https://login.example.com/callback", true},

		// Full URL pattern: exact host
		{"https://login.example.com/callback", "https://login.example.com/callback", true},
		{"https://login.example.com/other", "https://login.example.com/callback", false},

		// Full URL pattern: subdomain of configured host
		{"https://def.abc.com/callback", "abc.com", true},
		{"https://def.abc.com/callback", ".abc.com", true},
		{"https://def.abc.com/callback", ".abc.com/", true},
		{"https://deep.app.example.com/callback", "https://example.com/callback", true},

		// Full URL pattern: unrelated host must not match
		{"https://evil.com/callback", "https://example.com/callback", false},
		// Suffix collision: evilexample.com must not match example.com
		{"https://evilexample.com/callback", "https://example.com/callback", false},

		// Full URL pattern: scheme mismatch
		{"http://app.example.com/callback", "https://example.com/callback", false},

		// Full URL pattern: path mismatch
		{"https://app.example.com/other", "https://example.com/callback", false},

		// Scheme-less pattern: exact host
		{"https://login.example.com/callback", "login.example.com/callback", true},
		{"http://login.example.com/callback", "login.example.com/callback", true},

		// Scheme-less pattern: subdomain of configured host
		{"https://app.login.example.com/callback", "login.example.com/callback", true},

		// Scheme-less pattern: unrelated host must not match
		{"https://evil.com/callback", "login.example.com/callback", false},

		// Scheme-less pattern: query-string injection must not match
		{"https://evil.com/?r=https://login.example.com/callback", "login.example.com/callback", false},
		{"https://evil.com/page?redirect=https://login.example.com/callback", "login.example.com/callback", false},

		// Scheme-less pattern: path mismatch
		{"https://login.example.com/other", "login.example.com/callback", false},

		// Scheme-less pattern: non-http scheme must not match
		{"ftp://login.example.com/callback", "login.example.com/callback", false},

		// Empty target
		{"https://login.example.com/callback", "", false},
	}

	for _, tt := range tests {
		got := redirectUriMatchesPattern(tt.redirectUri, tt.targetUri)
		if got != tt.want {
			t.Errorf("redirectUriMatchesPattern(%q, %q) = %v, want %v", tt.redirectUri, tt.targetUri, got, tt.want)
		}
	}
}

// TestIsRedirectUriValidRejectsUnregisteredChromiumappOrigin asserts the
// invariant that the authorization server must not treat a redirect URI as
// valid unless the requesting application has explicitly registered it in
// its own RedirectUris list. util.IsValidOrigin previously granted a blanket
// pass to any "https://<anything>.chromiumapp.org/*" origin, so an
// application with an empty (or unrelated) RedirectUris list would still
// accept an attacker-chosen chromiumapp.org redirect URI, letting a browser
// extension author phish victims of any application on the instance.
func TestIsRedirectUriValidRejectsUnregisteredChromiumappOrigin(t *testing.T) {
	tests := []struct {
		name         string
		redirectUris []string
		redirectUri  string
		want         bool
	}{
		{
			name:         "arbitrary chromiumapp.org origin is rejected when the app has no registered redirect URIs",
			redirectUris: []string{},
			redirectUri:  "https://abcdefghijklmnopqrstuvwxyzabcdef.chromiumapp.org/oauth2",
			want:         false,
		},
		{
			name:         "control: an unrelated, non-chromiumapp.org origin is rejected the same way",
			redirectUris: []string{},
			redirectUri:  "https://evil.example.invalid/cb",
			want:         false,
		},
		{
			name:         "a chromiumapp.org origin is accepted once the app owner explicitly registers it",
			redirectUris: []string{"https://abcdefghijklmnopqrstuvwxyzabcdef.chromiumapp.org/oauth2"},
			redirectUri:  "https://abcdefghijklmnopqrstuvwxyzabcdef.chromiumapp.org/oauth2",
			want:         true,
		},
		{
			name:         "a different, unregistered chromiumapp.org origin is still rejected even when another one is registered",
			redirectUris: []string{"https://abcdefghijklmnopqrstuvwxyzabcdef.chromiumapp.org/oauth2"},
			redirectUri:  "https://xyzuniqueextid987654321.chromiumapp.org/callback",
			want:         false,
		},
		{
			name:         "control: a normally registered exact redirect URI is still accepted",
			redirectUris: []string{"https://login.example.com/callback"},
			redirectUri:  "https://login.example.com/callback",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &Application{RedirectUris: tt.redirectUris}
			got := app.IsRedirectUriValid(tt.redirectUri)
			if got != tt.want {
				t.Errorf("IsRedirectUriValid(%q) with RedirectUris=%v = %v, want %v", tt.redirectUri, tt.redirectUris, got, tt.want)
			}
		})
	}
}
