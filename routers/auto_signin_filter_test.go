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

package routers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// newFilterContext builds a minimal Beego context around an httptest request,
// mirroring how the AutoSigninFilter sees a request at runtime. It is DB-free:
// it exercises only credential *source* selection, not the credential check.
func newFilterContext(method, target, body string) *context.Context {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, reader)
	if body != "" {
		// Form body auto sign-in is submitted as URL-encoded form data.
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	ctx := context.NewContext()
	ctx.Reset(httptest.NewRecorder(), req)
	return ctx
}

// TestAutoSigninCredentialsRejectedFromQueryString is the regression test for
// the credential-in-URL auth bypass (routers/auto_signin_filter.go).
//
// Invariant: sign-in credentials (username/password) must NEVER be accepted from
// a URL query string. Placing them in the query string of any endpoint must not
// feed the auto sign-in credential check, because URL query strings are logged by
// servers/proxies/CDNs, saved in browser history and leaked via the Referer
// header — so accepting them there logs a victim in from a crafted link and hands
// their session to whoever later reads those logs.
//
// getAutoSigninUsernameAndPassword is the exact seam where the filter chooses the
// credential source. The test asserts the query string is ignored while the
// legitimate request body is honored, so the red is provably the invariant and
// not a broken environment.
func TestAutoSigninCredentialsRejectedFromQueryString(t *testing.T) {
	const (
		user = "org-alpha/alpha-user"
		pass = "some-password"
	)

	// --- Exploit case: credentials only in the URL query string (any method) ---
	// This is the attack: a crafted link carrying username/password. The filter
	// must NOT pick these up as auto sign-in credentials.
	for _, method := range []string{"GET", "POST"} {
		ctx := newFilterContext(method, "/api/get-captcha-status?username="+user+"&password="+pass, "")
		gotUser, gotPass, _ := getAutoSigninUsernameAndPassword(ctx)
		if gotUser != "" || gotPass != "" {
			t.Errorf("invariant violated: %s request with credentials in the URL query string was accepted as auto sign-in credentials (username=%q, password=%q); query-string credentials must be ignored so a crafted link cannot authenticate a victim",
				method, gotUser, gotPass)
		}
	}

	// --- Legitimate control: credentials in the POST request body ---
	// The intended body-based auto sign-in must keep working, proving the fix is
	// specific to the URL query string and did not just disable the feature.
	ctx := newFilterContext("POST", "/api/get-captcha-status", "username="+user+"&password="+pass)
	gotUser, gotPass, _ := getAutoSigninUsernameAndPassword(ctx)
	if gotUser != user || gotPass != pass {
		t.Fatalf("legitimate control broken: credentials in the POST body must be honored, got username=%q password=%q (want %q / %q)",
			gotUser, gotPass, user, pass)
	}
}
