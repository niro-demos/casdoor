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

//go:build !skipCi

package routers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// newCorsTestContext builds a real beego *context.Context around an
// httptest request/recorder pair, the same request/response types the
// running server hands to CorsFilter, so the filter is exercised exactly as
// it runs in production.
func newCorsTestContext(method, uri, host, origin string) (*beegoContext.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, uri, nil)
	req.Host = host
	if origin != "" {
		req.Header.Set(headerOrigin, origin)
	}

	w := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(w, req)
	return ctx, w
}

// TestCorsFilterUserinfoRejectsUntrustedOrigin is the regression test for
// TC-3FF0B537: GET /api/userinfo must not grant an arbitrary, unregistered
// cross-site origin a credentialed read of the caller's session, because
// that lets an attacker-controlled page exfiltrate a signed-in user's OIDC
// claims via fetch(..., {credentials:'include'}) using nothing but the
// victim's ambient session cookie.
//
// Invariant: the response to an untrusted Origin must NOT carry both
// Access-Control-Allow-Origin: <that origin> and
// Access-Control-Allow-Credentials: true - a browser only lets the calling
// page's JS read a credentialed cross-origin response when both favor the
// attacker.
func TestCorsFilterUserinfoRejectsUntrustedOrigin(t *testing.T) {
	object.InitConfig()

	evilOrigin := "https://evil-attacker.example"
	ctx, w := newCorsTestContext(http.MethodGet, "/api/userinfo", "casdoor.example.org:8000", evilOrigin)

	CorsFilter(ctx)

	acao := w.Header().Get(headerAllowOrigin)
	acac := w.Header().Get(headerAllowCredentials)

	if acao == evilOrigin && acac == "true" {
		t.Fatalf("GET /api/userinfo reflected untrusted Origin %q with Access-Control-Allow-Credentials: true "+
			"(Access-Control-Allow-Origin=%q, Access-Control-Allow-Credentials=%q) - "+
			"a cross-site attacker page can read the victim's authenticated userinfo claims", evilOrigin, acao, acac)
	}

	// Second, unrelated origin - rules out a fluke/one-off match.
	evilOrigin2 := "https://another-evil.test"
	ctx2, w2 := newCorsTestContext(http.MethodGet, "/api/userinfo", "casdoor.example.org:8000", evilOrigin2)

	CorsFilter(ctx2)

	acao2 := w2.Header().Get(headerAllowOrigin)
	acac2 := w2.Header().Get(headerAllowCredentials)

	if acao2 == evilOrigin2 && acac2 == "true" {
		t.Fatalf("GET /api/userinfo reflected a second untrusted Origin %q with Access-Control-Allow-Credentials: true "+
			"(Access-Control-Allow-Origin=%q, Access-Control-Allow-Credentials=%q)", evilOrigin2, acao2, acac2)
	}
}

// TestCorsFilterUserinfoAllowsSameHostOrigin is the control: a legitimate
// same-host request to /api/userinfo must keep working after the fix, so
// the red result above is proven to be about the untrusted-origin case
// specifically, not a broken filter.
func TestCorsFilterUserinfoAllowsSameHostOrigin(t *testing.T) {
	object.InitConfig()

	host := "casdoor.example.org:8000"
	sameHostOrigin := "https://casdoor.example.org:8000"
	ctx, w := newCorsTestContext(http.MethodGet, "/api/userinfo", host, sameHostOrigin)

	CorsFilter(ctx)

	acao := w.Header().Get(headerAllowOrigin)
	acac := w.Header().Get(headerAllowCredentials)

	if acao != sameHostOrigin || acac != "true" {
		t.Fatalf("GET /api/userinfo did not grant a legitimate same-host Origin %q cross-origin access "+
			"(Access-Control-Allow-Origin=%q, Access-Control-Allow-Credentials=%q) - the fix must not break same-host callers",
			sameHostOrigin, acao, acac)
	}
}
