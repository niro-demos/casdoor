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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// newMcpDenyTestContext builds a real Beego *context.Context wired to an
// httptest.ResponseRecorder, the same way Beego wires one for every filter
// invocation in the live BeforeRouter chain, so that ctx.ResponseWriter.Started
// reflects exactly what Beego's own router.go / filter.go check
// (`f.returnOnOutput && ctx.ResponseWriter.Started`) inspects to decide whether
// to keep routing to the protected controller.
func newMcpDenyTestContext(t *testing.T, method string, body []byte) (*context.Context, *httptest.ResponseRecorder) {
	t.Helper()

	req := httptest.NewRequest(method, "/api/server/niro-alpha/test-mcp-server", nil)
	rec := httptest.NewRecorder()

	ctx := context.NewContext()
	ctx.Reset(rec, req)
	// RequestBodyFilter normally populates this from the real request body
	// before ApiFilter runs; set it directly since we're calling
	// denyMcpRequest() as ApiFilter would, in isolation.
	ctx.Input.RequestBody = body

	return ctx, rec
}

// TestDenyMcpRequestAlwaysAnswersTheRequest asserts the invariant from
// TC-37ECEE63: every exit path of denyMcpRequest() must leave
// ctx.ResponseWriter.Started == true. That flag is exactly what Beego's
// BeforeRouter filter chain (github.com/beego/beego/v2/server/web/filter.go)
// checks to decide whether to short-circuit instead of invoking the matched
// controller. A caller authz.IsAllowed() has already denied must never reach
// ApiController.ProxyServer, regardless of whether their request body happens
// to parse as JSON.
func TestDenyMcpRequestAlwaysAnswersTheRequest(t *testing.T) {
	t.Run("well-formed body (positive control)", func(t *testing.T) {
		ctx, rec := newMcpDenyTestContext(t, http.MethodPost, []byte(`{"id":1,"jsonrpc":"2.0","method":"ping","params":{}}`))

		denyMcpRequest(ctx)

		if !ctx.ResponseWriter.Started {
			t.Fatalf("invariant violated: ctx.ResponseWriter.Started must be true so Beego stops routing to ProxyServer, got false")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected HTTP %d, got %d, body=%s", http.StatusUnauthorized, rec.Code, rec.Body.String())
		}

		var env struct {
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("expected a JSON deny envelope, got unparseable body %q: %v", rec.Body.String(), err)
		}
		if env.Error.Code != -32001 {
			t.Fatalf("expected deny envelope code -32001, got %d", env.Error.Code)
		}
	})

	t.Run("malformed body must still be answered, not fall through", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			method string
			body   []byte
		}{
			{"empty POST body", http.MethodPost, []byte("")},
			{"non-JSON POST body", http.MethodPost, []byte("not-json")},
			{"bare number POST body", http.MethodPost, []byte("123")},
			{"anonymous GET with no body", http.MethodGet, nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx, rec := newMcpDenyTestContext(t, tc.method, tc.body)

				denyMcpRequest(ctx)

				// This is the invariant: regardless of whether the body happens to
				// parse, denyMcpRequest must leave the request answered so Beego's
				// filter chain (ctx.ResponseWriter.Started) stops before invoking
				// the protected ProxyServer controller for a denied caller.
				if !ctx.ResponseWriter.Started {
					t.Fatalf("invariant violated: malformed body left ctx.ResponseWriter.Started == false, "+
						"so Beego's filter chain will NOT stop routing and will invoke the protected "+
						"ProxyServer controller for a caller authz.IsAllowed() already denied (got HTTP %d, body=%q)",
						rec.Code, rec.Body.String())
				}
				if rec.Code < 400 {
					t.Fatalf("expected an error status for a denied caller, got %d", rec.Code)
				}
				if rec.Body.Len() == 0 {
					t.Fatalf("expected a non-empty deny response body, got empty body with status %d", rec.Code)
				}
			})
		}
	})
}
