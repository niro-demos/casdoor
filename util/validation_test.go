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

package util

import "testing"

// TestIsValidOrigin covers the shared root cause of TC-D6CB84C3 and
// TC-6CC32273: IsValidOrigin used to grant an unconditional, application-
// agnostic pass to any origin/redirect_uri whose host (ignoring port) was
// "localhost", "127.0.0.1", "casdoor-authenticator", or suffixed with
// ".chromiumapp.org". That blanket pass was used both to grant credentialed
// CORS headers (routers/cors_filter.go, on every endpoint including
// GET /api/get-account) and to skip the OAuth redirect_uri allow-list
// (object/application_util.go IsRedirectUriValid), for every application in
// the instance, regardless of what that application actually registered.
//
// IsValidOrigin no longer grants any origin a special pass -- trust is
// established solely by matching against the specific application's own
// registered RedirectUris (see object.Application.IsRedirectUriValid /
// IsOriginValid). This test asserts that invariant directly at the shared
// root-cause function.
func TestIsValidOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
	}{
		{"arbitrary localhost port", "http://localhost:65000"},
		{"arbitrary localhost port (https)", "https://localhost:65000"},
		{"arbitrary 127.0.0.1 port", "http://127.0.0.1:9999"},
		{"127.0.0.1 with no port", "http://127.0.0.1"},
		{"casdoor-authenticator pseudo-origin", "http://casdoor-authenticator"},
		{"chromiumapp.org extension origin", "https://attackerextensionid.chromiumapp.org/"},
		{"ordinary unrelated origin", "http://evil.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsValidOrigin(tt.origin)
			if err != nil {
				t.Fatalf("IsValidOrigin(%q) returned unexpected error: %v", tt.origin, err)
			}
			if got {
				t.Errorf("IsValidOrigin(%q) = true, want false: no origin should get a blanket, application-agnostic pass", tt.origin)
			}
		})
	}
}

// TestIsValidOriginRejectsMalformedOrigin preserves the pre-existing
// behavior of surfacing a url.Parse error for a malformed origin, so callers
// that branch on the error (e.g. CorsFilter, IsOriginValid) keep working.
func TestIsValidOriginRejectsMalformedOrigin(t *testing.T) {
	_, err := IsValidOrigin("http://[::1")
	if err == nil {
		t.Fatal("IsValidOrigin(malformed origin) returned nil error, want a parse error")
	}
}
