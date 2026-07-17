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

// TestIsRedirectUriValid covers TC-6CC32273: the OAuth authorization
// endpoint must only ever hand a code/login response to a redirect_uri the
// requesting application actually registered in its own RedirectUris,
// regardless of whether the unregistered URI's host happens to be
// localhost, 127.0.0.1, casdoor-authenticator, or a *.chromiumapp.org
// browser-extension host. Those hosts were previously special-cased as
// unconditionally valid by util.IsValidOrigin, bypassing the RedirectUris
// allow-list entirely for every application in the instance.
func TestIsRedirectUriValid(t *testing.T) {
	// Mirrors app-acme from the finding: only one redirect_uri registered.
	application := &Application{
		Owner:        "admin",
		Name:         "app-acme",
		RedirectUris: []string{"http://localhost:8000/callback"},
	}

	tests := []struct {
		name        string
		redirectUri string
		want        bool
	}{
		// Positive control: the application's actually-registered redirect_uri
		// must keep working -- proves the allow-list check itself isn't broken.
		{"registered redirect_uri is accepted", "http://localhost:8000/callback", true},

		// Negative control: an ordinary unregistered host was already rejected
		// before this fix; it must stay rejected.
		{"plain unregistered host is rejected", "http://evil.example.com/callback", false},

		// Attack cases from TC-6CC32273's attack_steps: none of these are in
		// app-acme's RedirectUris, so all must be rejected -- previously they
		// were unconditionally accepted via util.IsValidOrigin's blanket
		// localhost/127.0.0.1/chromiumapp.org bypass.
		{"unregistered localhost port is rejected", "http://localhost:31337/exfil", false},
		{"unregistered 127.0.0.1 port is rejected", "http://127.0.0.1:4444/exfil", false},
		{"unregistered chromiumapp.org host is rejected", "https://attackerextensionid.chromiumapp.org/", false},
		{"unregistered localhost port (2nd case) is rejected", "http://localhost:9999/exfil2", false},
		{"unregistered casdoor-authenticator host is rejected", "http://casdoor-authenticator/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := application.IsRedirectUriValid(tt.redirectUri)
			if got != tt.want {
				t.Errorf("IsRedirectUriValid(%q) = %v, want %v", tt.redirectUri, got, tt.want)
			}
		})
	}
}

// TestIsOriginValid covers the object-level half of TC-D6CB84C3: the
// application-scoped CORS allow-list (used by CorsFilter via
// IsOriginAllowed for every credentialed endpoint, including
// GET /api/get-account) must only grant a credentialed cross-origin match
// to an Origin the application actually registered (scheme+host+port), not
// to an arbitrary Origin that merely claims a localhost/127.0.0.1 host.
func TestIsOriginValid(t *testing.T) {
	// Mirrors app-acme: its only registered redirect_uri is on localhost:8000,
	// so that exact origin is legitimately trusted for CORS.
	application := &Application{
		Owner:        "admin",
		Name:         "app-acme",
		RedirectUris: []string{"http://localhost:8000/callback"},
	}

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		// Positive control: the app's own registered origin (scheme+host+port)
		// must still be granted -- proves the allow-list itself isn't broken.
		{"registered origin is valid", "http://localhost:8000", true},

		// Attack case from TC-D6CB84C3's attack_steps: an arbitrary,
		// unregistered localhost port unrelated to this application must NOT
		// be granted a credentialed CORS match -- previously it was, via
		// util.IsValidOrigin's blanket localhost bypass.
		{"forged unregistered localhost port is rejected", "http://localhost:65000", false},
		{"forged unregistered 127.0.0.1 port is rejected", "http://127.0.0.1:9999", false},

		// A plain unrelated origin was already rejected; must stay rejected.
		{"unrelated origin is rejected", "http://evil.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := application.IsOriginValid(tt.origin)
			if got != tt.want {
				t.Errorf("IsOriginValid(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}
