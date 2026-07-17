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

//go:build !skipCi

package controllers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
)

// callSendEmail drives controllers.ApiController.SendEmail() directly, the
// same way beego's router would after its filters ran — except that here we
// stand in for the ApiFilter by stashing "currentUserId" on the context
// ourselves, which is exactly what routers.ApiFilter does after a successful
// clientId/clientSecret or session lookup (see GetSessionUsername in
// controllers/base.go: "prefer username stored in Beego context by
// ApiFilter"). This lets the test exercise the real controller method without
// standing up beego's full session/auth middleware stack.
//
// Returns the HTTP status code beego would have written and the parsed
// Response body. If the handler panics (the bug under test), the panic is
// recovered and reported via t.Fatalf so a single failing case doesn't take
// down the rest of the suite — a real HTTP server would have turned this
// same panic into beego's HTML debug page.
func callSendEmail(t *testing.T, currentUserId string, body string) (int, *controllers.Response) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/send-email", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(w, req)
	ctx.Input.RequestBody = []byte(body)
	ctx.Input.SetData("currentUserId", currentUserId)

	c := &controllers.ApiController{}
	c.Init(ctx, "ApiController", "SendEmail", nil)

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SendEmail panicked instead of returning a clean error: %v", r)
			}
		}()
		c.SendEmail()
	}()

	resp := &controllers.Response{}
	if err := json.Unmarshal(w.Body.Bytes(), resp); err != nil {
		t.Fatalf("response body was not valid JSON (status=%d): %q, unmarshal error: %v", w.Code, w.Body.String(), err)
	}
	return w.Code, resp
}

// TestSendEmailUnknownProviderReturnsCleanError is the regression test for
// TC-3AD6B5B3: POST /api/send-email with a "provider" name that does not
// exist for the caller's application must return a clean JSON error, not
// crash the handler with a nil-pointer panic (which, served over real HTTP,
// renders beego's debug error page — a full stack trace, source file paths,
// and the request's own clientId/clientSecret query params echoed back).
//
// Root cause (controllers/service.go SendEmail): when emailForm.Provider is
// set, the handler calls object.GetProvider(...) and only checks the
// returned error — but object.GetProvider returns (nil, nil), not an error,
// when no Provider row matches the name. The nil provider then flows
// unchecked into object.SendEmail(), which immediately dereferences it.
func TestSendEmailUnknownProviderReturnsCleanError(t *testing.T) {
	object.InitConfig()

	const userId = "app/app-built-in"

	// --- Positive control -------------------------------------------------
	// Omit the "provider" field entirely. This exercises the sibling branch
	// (GetProviderFromContext) which already has a nil/not-found check and
	// therefore already returns a clean, graceful JSON error today. This
	// must stay green in both the unfixed and fixed code — it proves the
	// authenticated-request plumbing in this test is healthy, so a failure
	// on the bogus-provider case below is isolated to the real bug, not a
	// broken test harness.
	t.Run("control: no provider field is already handled gracefully", func(t *testing.T) {
		controlBody := `{"title":"t","content":"c","sender":"s","receivers":["a@b.com"]}`
		status, resp := callSendEmail(t, userId, controlBody)

		if status != http.StatusOK {
			t.Fatalf("expected HTTP 200 for the already-handled no-provider case, got %d", status)
		}
		if resp.Status != "error" {
			t.Fatalf("expected a graceful error response, got status=%q msg=%q", resp.Status, resp.Msg)
		}
		if !strings.Contains(resp.Msg, "No provider for category") {
			t.Fatalf("expected the existing graceful 'no provider configured' message, got msg=%q", resp.Msg)
		}
	})

	// --- Red check: the invariant ------------------------------------------
	// A provider name that does not exist for this owner must produce the
	// same kind of clean JSON error as the control above (HTTP 200, a
	// {"status":"error",...} body) — never a panic and never beego's HTML
	// debug page.
	bogusNames := []string{
		"this_provider_does_not_exist_xyz_regression_test",
		"another_bogus_provider_zzz_regression_test",
	}

	for _, name := range bogusNames {
		name := name
		t.Run(fmt.Sprintf("unknown provider %q returns a clean error, not a panic", name), func(t *testing.T) {
			body := fmt.Sprintf(`{"title":"t","content":"c","sender":"s","receivers":["a@b.com"],"provider":%q}`, name)
			status, resp := callSendEmail(t, userId, body)

			if status != http.StatusOK {
				t.Fatalf("expected a clean HTTP 200 JSON error for unknown provider %q (matching the sibling no-provider-configured case), got HTTP %d", name, status)
			}
			if resp.Status != "error" {
				t.Fatalf("expected a graceful error response for unknown provider %q, got status=%q msg=%q (HTTP %d)", name, resp.Status, resp.Msg, status)
			}
			if !strings.Contains(resp.Msg, name) {
				t.Fatalf("expected the error message to name the missing provider %q, got msg=%q", name, resp.Msg)
			}
		})
	}
}
