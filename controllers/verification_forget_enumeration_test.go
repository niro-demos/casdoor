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

package controllers

// Regression test for TC-C78E3181: unauthenticated username enumeration via
// POST /api/send-verification-code (method=forget).
//
// Invariant under test: the forgot-password verification-code request must
// not reveal whether a given username exists in an organization to an
// unauthenticated caller. Concretely: for a fixed, unrelated `dest` email
// (any known-valid account email in the org), the response must not differ
// between a `checkUser` that names a real, unrelated account and a
// `checkUser` that names no account at all.
//
// This exercises the running HTTP server end to end (there is no existing
// controllers-level unit-test harness in this project that stubs out the
// beego request/DB stack), matching the org/app/user fixtures seeded by
// niro/harness/init_data.seed.json ("acme" org, "app-acme" application with
// no email provider configured, users alice/bob/acme-admin). It targets
// CASDOOR_TEST_BASE_URL (default http://localhost:8000, the harness's
// default) and skips when that server isn't reachable, so `go test ./...`
// stays green without a live instance.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func forgetVerificationTestBaseURL() string {
	if v := os.Getenv("CASDOOR_TEST_BASE_URL"); v != "" {
		return v
	}
	return "http://localhost:8000"
}

func requireLiveServerForForgetVerificationTest(t *testing.T, baseURL string) {
	t.Helper()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(baseURL + "/api/health")
	if err != nil {
		t.Skipf("skipping: no live Casdoor server at %s (%v) — start niro/harness/start.sh (or point CASDOOR_TEST_BASE_URL at a running instance) to run this regression test", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("skipping: %s/api/health returned %d, server not healthy", baseURL, resp.StatusCode)
	}
}

type sendVerificationCodeResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

func callSendVerificationCode(t *testing.T, baseURL, dest, checkUser string) sendVerificationCodeResponse {
	t.Helper()

	form := url.Values{}
	form.Set("dest", dest)
	form.Set("type", "email")
	form.Set("applicationId", "admin/app-acme")
	form.Set("method", "forget")
	form.Set("checkUser", checkUser)
	form.Set("captchaType", "none")

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/send-verification-code", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request for checkUser=%q failed: %v", checkUser, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body for checkUser=%q: %v", checkUser, err)
	}

	var parsed sendVerificationCodeResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse JSON response for checkUser=%q (status %d): %s: %v", checkUser, resp.StatusCode, string(body), err)
	}
	return parsed
}

// TestForgetVerificationCodeDoesNotLeakUsernameExistence asserts that an
// anonymous caller cannot use POST /api/send-verification-code (method=forget)
// as a username-existence oracle by pairing an arbitrary valid `dest` email
// with different `checkUser` values.
func TestForgetVerificationCodeDoesNotLeakUsernameExistence(t *testing.T) {
	baseURL := forgetVerificationTestBaseURL()
	requireLiveServerForForgetVerificationTest(t, baseURL)

	// A fixed, unrelated pivot value: alice's real, valid email in the acme
	// org. Per the finding, it does not need to belong to the probed
	// checkUser at all.
	const pivotDest = "alice@acme.example.com"

	nonexistentUser := "zzz_ghost_niro_regression_does_not_exist"

	nonexistentResp := callSendVerificationCode(t, baseURL, pivotDest, nonexistentUser)

	// Real, but unrelated to pivotDest, accounts.
	for _, realUser := range []string{"bob", "acme-admin"} {
		t.Run("checkUser="+realUser, func(t *testing.T) {
			realResp := callSendVerificationCode(t, baseURL, pivotDest, realUser)

			if realResp.Msg != nonexistentResp.Msg {
				t.Fatalf("invariant violated: response for real, unrelated checkUser=%q (%q) differs from response for a nonexistent checkUser (%q) — an anonymous caller can distinguish valid from invalid usernames via this endpoint",
					realUser, realResp.Msg, nonexistentResp.Msg)
			}
		})
	}

	// Control: a legitimate, matching pair (checkUser resolves AND owns
	// pivotDest) must still proceed past the existence check to the next
	// stage (app-acme has no email provider configured, so it fails there
	// instead) — proving the fix rejects mismatched pairs specifically,
	// not all forget-password requests.
	t.Run("control: matching checkUser and dest still proceed", func(t *testing.T) {
		matchedResp := callSendVerificationCode(t, baseURL, pivotDest, "alice")

		if matchedResp.Msg == nonexistentResp.Msg {
			t.Fatalf("control failed: a legitimate matching checkUser=dest pair (alice / %s) produced the same response as a nonexistent user (%q) — the environment or test setup is broken, not just the security check",
				pivotDest, nonexistentResp.Msg)
		}
	})
}
