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

// TestCorsFilterMalformedOriginDoesNotPanic asserts the invariant behind
// TC-89925A92: "Sending a malformed Origin header must not crash the
// request handler or return an internal debug page with a source-code
// stack trace to an unauthenticated caller."
//
// CorsFilter is beego's global pre-auth filter, so any unrecovered panic
// inside it surfaces (in the shipped dev runmode) as a 500 response with a
// full stack trace before authentication ever runs. A well-formed request
// with no Origin header is run first as a positive control, proving the
// target/filter is healthy so the failure below is specific to the
// malformed value, not a broken test setup.
func TestCorsFilterMalformedOriginDoesNotPanic(t *testing.T) {
	runFilter := func(origin string) (status int, panicVal interface{}) {
		req := httptest.NewRequest(http.MethodGet, "/api/get-account", nil)
		if origin != "" {
			req.Header.Set(headerOrigin, origin)
		}
		w := httptest.NewRecorder()

		ctx := context.NewContext()
		ctx.Reset(w, req)

		defer func() {
			panicVal = recover()
		}()

		CorsFilter(ctx)
		return w.Code, nil
	}

	// Positive control: no Origin header at all must not panic and must not
	// 500 - proves the harness/filter is healthy.
	if status, panicVal := runFilter(""); panicVal != nil {
		t.Fatalf("positive control: CorsFilter panicked on a request with no Origin header: %v", panicVal)
	} else if status >= http.StatusInternalServerError {
		t.Fatalf("positive control: CorsFilter returned a server error (status=%d) on a request with no Origin header", status)
	}

	// The exploit: an Origin header that fails Go's url.Parse (a hostname
	// immediately followed by a non-numeric string after a colon).
	malformedOrigin := "http://localhost:8000.evil.com"
	status, panicVal := runFilter(malformedOrigin)
	if panicVal != nil {
		t.Fatalf("invariant violated: CorsFilter panicked on malformed Origin header %q: %v\n(beego turns an unrecovered pre-auth panic into a 500 debug page with a source-code stack trace)", malformedOrigin, panicVal)
	}
	if status >= http.StatusInternalServerError {
		t.Fatalf("invariant violated: CorsFilter returned status=%d for malformed Origin header %q; expected an ordinary 4xx rejection, not a server error", status, malformedOrigin)
	}
}
