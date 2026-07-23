// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

package routers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// Security regression tests for CorsFilter (routers/cors_filter.go).
//
// Invariant: a malicious website must not be able to read a logged-in user's
// identity from Casdoor via a cross-site credentialed request. For an arbitrary
// attacker Origin, CorsFilter must not answer with the credential-allowing CORS
// headers (Access-Control-Allow-Origin: <attacker> + Access-Control-Allow-Credentials: true)
// that a browser requires to expose the response body to attacker JavaScript.
//
// Two ways the pre-fix filter violated this:
//   - TC-648A0C3B: /api/userinfo (and POST /api/login/oauth/access_token,
//     POST /api/acs) unconditionally reflected the raw Origin, bypassing the
//     allow-list entirely.
//   - TC-E67E33C8: the fallback branches trusted the caller-supplied Host header
//     (originHostname == host, and IsHostIntranet(host)), so spoofing Host to
//     match the attacker Origin — or to a loopback value — reflected any Origin.
//
// These tests drive the real CorsFilter. The DB-backed application allow-list
// (corsIsOriginAllowed) is stubbed to deny everything, so the environment needs
// no database and any reflected attacker Origin is provably the filter's own
// bug, not a seeded allow-list entry.

const attackerOrigin = "https://evil-attacker.example"

// runCorsFilter builds a beego context for the given method/URI/Host/Origin,
// runs CorsFilter, and returns the response recorder's headers.
func runCorsFilter(t *testing.T, method, requestURI, host, origin string) http.Header {
	t.Helper()

	req := httptest.NewRequest(method, "http://"+host+requestURI, nil)
	req.Host = host
	req.RequestURI = requestURI
	if origin != "" {
		req.Header.Set(headerOrigin, origin)
	}

	rec := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(rec, req)

	CorsFilter(ctx)
	return rec.Header()
}

// assertNoCredentialedReflection fails if the attacker Origin was reflected with
// credentials allowed — the exact combination a browser needs to expose an
// authenticated cross-origin response body to attacker JavaScript.
func assertNoCredentialedReflection(t *testing.T, h http.Header, label string) {
	t.Helper()
	acao := h.Get(headerAllowOrigin)
	acac := h.Get(headerAllowCredentials)
	if acao == attackerOrigin && acac == "true" {
		t.Errorf("%s: attacker Origin reflected with credentials allowed "+
			"(Access-Control-Allow-Origin=%q, Access-Control-Allow-Credentials=%q); "+
			"a browser would expose the authenticated response to attacker JavaScript",
			label, acao, acac)
	}
}

// stubDenyAllOrigins forces the DB-backed allow-list to deny every origin, so
// the tests run without a database and no origin is allowed by seeded data.
func stubDenyAllOrigins(t *testing.T) {
	t.Helper()
	prev := corsIsOriginAllowed
	corsIsOriginAllowed = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() { corsIsOriginAllowed = prev })
}

// TC-648A0C3B: /api/userinfo (and the other unconditional carve-outs) must not
// reflect an arbitrary attacker Origin with credentials.
func TestCorsFilter_UserinfoCarveOut_DoesNotReflectAttackerOrigin(t *testing.T) {
	stubDenyAllOrigins(t)

	// The carve-out routes flagged by the finding's remediation guidance.
	cases := []struct {
		name       string
		method     string
		requestURI string
	}{
		{"userinfo", "GET", "/api/userinfo"},
		{"access_token", "POST", "/api/login/oauth/access_token"},
		{"acs", "POST", "/api/acs"},
	}
	// The victim's own host — no Host spoofing here; the carve-out alone is the bug.
	const legitHost = "casdoor.example:8000"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := runCorsFilter(t, tc.method, tc.requestURI, legitHost, attackerOrigin)
			assertNoCredentialedReflection(t, h, tc.name)
		})
	}
}

// TC-E67E33C8: the CORS decision must not trust the caller-supplied Host header.
func TestCorsFilter_HostSpoof_DoesNotReflectAttackerOrigin(t *testing.T) {
	stubDenyAllOrigins(t)

	// Exploit A: Host set equal to the attacker Origin's hostname.
	t.Run("host_equals_origin_hostname", func(t *testing.T) {
		h := runCorsFilter(t, "POST", "/api/mcp", "evil-attacker.example", attackerOrigin)
		assertNoCredentialedReflection(t, h, "host==origin hostname")
	})

	// Exploit B: loopback-looking Host, a completely unrelated attacker Origin.
	t.Run("loopback_host", func(t *testing.T) {
		const otherOrigin = "https://totally-different-evil.example"
		h := runCorsFilter(t, "POST", "/api/mcp", "127.0.0.1", otherOrigin)
		acao := h.Get(headerAllowOrigin)
		acac := h.Get(headerAllowCredentials)
		if acao == otherOrigin && acac == "true" {
			t.Errorf("loopback-Host bypass: attacker Origin reflected with credentials "+
				"(Access-Control-Allow-Origin=%q, Access-Control-Allow-Credentials=%q)", acao, acac)
		}
	})
}

// Positive controls: legitimate, server-known origins must still be allowed, so
// the tests above prove the bug is specific and the fix is not a blanket denial
// that would break real cross-origin clients.
func TestCorsFilter_LegitimateOrigins_StillAllowed(t *testing.T) {
	stubDenyAllOrigins(t) // even with the DB allow-list empty, these must pass.

	// localhost is a server-known safe origin (util.IsValidOrigin).
	t.Run("localhost_userinfo", func(t *testing.T) {
		const good = "http://localhost"
		h := runCorsFilter(t, "GET", "/api/userinfo", "casdoor.example:8000", good)
		if got := h.Get(headerAllowOrigin); got != good {
			t.Errorf("legitimate Origin %q was not allowed on /api/userinfo (ACAO=%q)", good, got)
		}
		if got := h.Get(headerAllowCredentials); got != "true" {
			t.Errorf("legitimate Origin %q did not get Access-Control-Allow-Credentials:true (got %q)", good, got)
		}
	})
}
