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

// Regression tests for POST /api/upload-resource authorization.
//
// These are black-box HTTP integration tests that run against a live Casdoor
// instance (the same shape of target the project's Niro harness under
// niro/harness/ stands up). They exercise controllers.ApiController.UploadResource
// and controllers.ApiController.GetProviderFromContext exactly the way an
// external client would, because the bugs they guard against are HTTP-boundary
// authorization bypasses (spoofable owner/user query params, and an
// authentication short-circuit keyed off the `provider` query param) that
// cannot be observed by calling Go functions directly in-process.
//
// Point TARGET_URL at a running instance (defaults to the local Niro harness
// at http://127.0.0.1:18000, see niro/harness/start.sh). If no instance is
// reachable, the tests skip rather than fail, consistent with other
// infrastructure-dependent tests in this repository (e.g. object package
// tests that require a live MySQL).
package controllers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	testOrg             = "niro-test"
	testApplication     = "app-niro-test"
	testStorageProvider = "provider-niro-local-storage"

	globalAdminUsername = "admin"
	globalAdminPassword = "123"
	globalAdminOrg      = "built-in"
	globalAdminApp      = "app-built-in"

	aliceUsername = "alice"
	alicePassword = "NiroPass123"

	bobUsername = "bob"
	bobPassword = "NiroPass123"

	orgAdminUsername = "org-admin"
	orgAdminPassword = "NiroPass123"
)

type uploadAuthzResponse struct {
	Status string      `json:"status"`
	Msg    string      `json:"msg"`
	Data   interface{} `json:"data"`
}

func testTargetURL() string {
	if v := os.Getenv("TARGET_URL"); v != "" {
		return v
	}
	return "http://127.0.0.1:18000"
}

// requireLiveTarget skips the test if no Casdoor instance answers at
// testTargetURL(). These tests need a real, running server (session cookies,
// storage provider, DB-backed users) and cannot be satisfied by an in-process
// fake, so absence of a reachable target is treated as "cannot run here", not
// as a failure.
func requireLiveTarget(t *testing.T) {
	t.Helper()
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(testTargetURL() + "/api/health")
	if err != nil {
		t.Skipf("skipping: no Casdoor instance reachable at %s (%v); start it via niro/harness/start.sh or set TARGET_URL", testTargetURL(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("skipping: Casdoor instance at %s is not healthy (http %d)", testTargetURL(), resp.StatusCode)
	}
}

func newAuthzTestClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("could not create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 30 * time.Second}
}

func authzLogin(t *testing.T, client *http.Client, application, organization, username, password string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"application":  application,
		"organization": organization,
		"username":     username,
		"password":     password,
		"type":         "login",
		"signinMethod": "Password",
	})
	req, err := http.NewRequest(http.MethodPost, testTargetURL()+"/api/login", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request for %s/%s failed: %v", organization, username, err)
	}
	defer resp.Body.Close()

	var parsed uploadAuthzResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("login response for %s/%s: could not parse: %v", organization, username, err)
	}
	if parsed.Status != "ok" {
		t.Fatalf("login as %s/%s failed (harness precondition): %s", organization, username, parsed.Msg)
	}
}

// authzUploadResource performs the multipart POST /api/upload-resource call.
// provider, when non-empty, is appended as a query parameter (mirrors how a
// caller can force provider resolution instead of going through the signed-in
// application's default storage provider).
func authzUploadResource(t *testing.T, client *http.Client, owner, user, tag, fullFilePath, provider string, content []byte) (*uploadAuthzResponse, int) {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "poc.bin")
	if err != nil {
		t.Fatalf("creating multipart file field: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("writing multipart content: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing multipart writer: %v", err)
	}

	url := fmt.Sprintf("%s/api/upload-resource?owner=%s&user=%s&application=%s&tag=%s&fullFilePath=%s",
		testTargetURL(), owner, user, testApplication, tag, fullFilePath)
	if provider != "" {
		url += "&provider=" + provider
	}

	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		t.Fatalf("building upload-resource request: %v", err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upload-resource request errored: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading upload-resource response: %v", err)
	}
	var parsed uploadAuthzResponse
	_ = json.Unmarshal(raw, &parsed) // best-effort: some rejections may not be JSON

	return &parsed, resp.StatusCode
}

func authzGetJSON(t *testing.T, client *http.Client, url string, out interface{}) {
	t.Helper()
	var resp *http.Response
	var err error
	if client != nil {
		resp, err = client.Get(url)
	} else {
		resp, err = http.Get(url)
	}
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("GET %s: could not decode response: %v", url, err)
	}
}

func authzAddApplication(t *testing.T, admin *http.Client, name string) {
	t.Helper()
	app := map[string]interface{}{
		"owner":          "admin",
		"name":           name,
		"createdTime":    time.Now().UTC().Format(time.RFC3339),
		"displayName":    "TC-B0CA2E8B regression test app",
		"organization":   testOrg,
		"enablePassword": true,
		"termsOfUse":     "",
	}
	b, _ := json.Marshal(app)
	req, err := http.NewRequest(http.MethodPost, testTargetURL()+"/api/add-application?columns=", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("building add-application request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatalf("add-application request failed: %v", err)
	}
	defer resp.Body.Close()
	var parsed uploadAuthzResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("add-application: could not parse response: %v", err)
	}
	if parsed.Status != "ok" {
		t.Fatalf("add-application failed (harness precondition): %s", parsed.Msg)
	}
}

func authzDeleteApplication(t *testing.T, admin *http.Client, name string) {
	t.Helper()
	app := map[string]string{"owner": "admin", "name": name, "organization": testOrg}
	b, _ := json.Marshal(app)
	req, err := http.NewRequest(http.MethodPost, testTargetURL()+"/api/delete-application", bytes.NewReader(b))
	if err != nil {
		t.Logf("WARNING: could not build cleanup delete-application request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := admin.Do(req)
	if err != nil {
		t.Logf("WARNING: cleanup delete-application request failed, please delete admin/%s manually: %v", name, err)
		return
	}
	defer resp.Body.Close()
}

// TestUploadResource_TermsOfUse_RequiresRealAdminSession is the regression
// test for TC-B0CA2E8B: the "termsOfUse" branch of UploadResource must check
// the actual logged-in session's admin status, not the admin status of
// whatever owner/user the caller names in the query string.
func TestUploadResource_TermsOfUse_RequiresRealAdminSession(t *testing.T) {
	requireLiveTarget(t)

	admin := newAuthzTestClient(t)
	authzLogin(t, admin, globalAdminApp, globalAdminOrg, globalAdminUsername, globalAdminPassword)

	appName := fmt.Sprintf("app-tc-b0ca2e8b-regress-%d", time.Now().UnixNano())
	authzAddApplication(t, admin, appName)
	defer authzDeleteApplication(t, admin, appName)

	var before struct {
		Status string `json:"status"`
		Data   struct {
			TermsOfUse string `json:"termsOfUse"`
		} `json:"data"`
	}
	authzGetJSON(t, admin, testTargetURL()+"/api/get-application?id=admin/"+appName, &before)
	if before.Data.TermsOfUse != "" {
		t.Fatalf("harness precondition violated: freshly created application already has termsOfUse=%q", before.Data.TermsOfUse)
	}

	alice := newAuthzTestClient(t)
	authzLogin(t, alice, testApplication, testOrg, aliceUsername, alicePassword)

	// --- Attack: alice (a plain standard user) claims owner=built-in&user=admin
	// in the query string while uploading termsOfUse for the throwaway app. ---
	marker := fmt.Sprintf("vector-tc-b0ca2e8b-%d", time.Now().UnixNano())
	evilHTML := fmt.Sprintf("<html><body><script>alert('%s')</script></body></html>", marker)
	fullFilePath := fmt.Sprintf("termsOfUse/admin/%s.html", appName)
	exploitResp, _ := authzUploadResource(t, alice, "built-in", "admin", "termsOfUse", fullFilePath, testStorageProvider, []byte(evilHTML))

	var after struct {
		Status string `json:"status"`
		Data   struct {
			TermsOfUse string `json:"termsOfUse"`
		} `json:"data"`
	}
	authzGetJSON(t, admin, testTargetURL()+"/api/get-application?id=admin/"+appName, &after)

	// Invariant: a non-admin session must never be able to set this
	// application's termsOfUse, regardless of which owner/user it names.
	if exploitResp.Status == "ok" || strings.Contains(after.Data.TermsOfUse, marker) {
		t.Fatalf("invariant violated: alice (non-admin), spoofing owner=built-in&user=admin, "+
			"set termsOfUse. response=%+v application.termsOfUse=%q", *exploitResp, after.Data.TermsOfUse)
	}

	// --- Positive control: the real admin session, using its own identity,
	// must still be able to set termsOfUse. Proves the environment/endpoint
	// is healthy and the rejection above is the authorization check, not a
	// broken target. ---
	posMarker := fmt.Sprintf("legit-%d", time.Now().UnixNano())
	posHTML := fmt.Sprintf("<html><body>%s</body></html>", posMarker)
	posResp, _ := authzUploadResource(t, admin, "built-in", "admin", "termsOfUse", fullFilePath, testStorageProvider, []byte(posHTML))
	if posResp.Status != "ok" {
		t.Fatalf("positive control failed: real admin's own termsOfUse upload was rejected: %s", posResp.Msg)
	}
}

// TestUploadResource_UserOwnedTags_RequireOwnershipOrAdmin is the regression
// test for TC-2A71F589: the "avatar" and "idCardFront"/"idCardBack"/
// "idCardWithPerson" branches of UploadResource must reject a caller who is
// neither the target user nor an admin, instead of trusting the owner/user
// query parameters unconditionally.
func TestUploadResource_UserOwnedTags_RequireOwnershipOrAdmin(t *testing.T) {
	requireLiveTarget(t)

	tags := []string{"avatar", "idCardFront"}

	// Read back victim state as the global admin so masked fields (like
	// Properties, which an anonymous/self-only viewer never sees) are
	// visible enough to prove whether the attack actually mutated them.
	admin := newAuthzTestClient(t)
	authzLogin(t, admin, globalAdminApp, globalAdminOrg, globalAdminUsername, globalAdminPassword)

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			alice := newAuthzTestClient(t)
			authzLogin(t, alice, testApplication, testOrg, aliceUsername, alicePassword)

			victimID := testOrg + "/" + bobUsername
			var baseline struct {
				Status string `json:"status"`
				Data   struct {
					Avatar     string            `json:"avatar"`
					Properties map[string]string `json:"properties"`
				} `json:"data"`
			}
			authzGetJSON(t, admin, testTargetURL()+"/api/get-user?id="+victimID, &baseline)

			nonce := time.Now().UnixNano()

			// --- Positive control: alice uploads to her OWN slot. Must succeed,
			// proving the endpoint and storage provider are healthy. ---
			selfPath := fmt.Sprintf("verify-self-%s-%d.png", tag, nonce)
			selfResp, _ := authzUploadResource(t, alice, testOrg, aliceUsername, tag, selfPath, "", pngBytes())
			if selfResp.Status != "ok" {
				t.Fatalf("positive control failed: alice's own %s upload was rejected: %s", tag, selfResp.Msg)
			}

			// --- Attack: alice uploads into bob's slot by naming bob in
			// owner/user, without any ownership or admin check. ---
			crossPath := fmt.Sprintf("verify-cross-%s-%d.png", tag, nonce)
			crossResp, _ := authzUploadResource(t, alice, testOrg, bobUsername, tag, crossPath, "", pngBytes())

			var afterAttack struct {
				Status string `json:"status"`
				Data   struct {
					Avatar     string            `json:"avatar"`
					Properties map[string]string `json:"properties"`
				} `json:"data"`
			}
			authzGetJSON(t, admin, testTargetURL()+"/api/get-user?id="+victimID, &afterAttack)

			victimChanged := false
			if tag == "avatar" {
				victimChanged = afterAttack.Data.Avatar != baseline.Data.Avatar && strings.Contains(afterAttack.Data.Avatar, crossPath)
			} else {
				victimChanged = afterAttack.Data.Properties[tag] != baseline.Data.Properties[tag] && strings.Contains(afterAttack.Data.Properties[tag], crossPath)
			}

			if crossResp.Status == "ok" || victimChanged {
				t.Fatalf("invariant violated: alice, a plain standard user, overwrote bob's %s with no ownership/admin check. "+
					"response=%+v before=%+v after=%+v", tag, *crossResp, baseline.Data, afterAttack.Data)
			}
		})
	}
}

// TestUploadResource_OrgAdmin_CanStillEditOtherUsersAvatar documents the
// legitimate admin-on-behalf-of-user behavior the ownership fix must
// preserve: an org admin editing another user's avatar (the exact workflow
// UserEditPage's CropperDivModal drives for Setting.isLocalAdminUser(account))
// must keep working.
func TestUploadResource_OrgAdmin_CanStillEditOtherUsersAvatar(t *testing.T) {
	requireLiveTarget(t)

	orgAdmin := newAuthzTestClient(t)
	authzLogin(t, orgAdmin, testApplication, testOrg, orgAdminUsername, orgAdminPassword)

	nonce := time.Now().UnixNano()
	path := fmt.Sprintf("org-admin-edits-bob-%d.png", nonce)
	resp, _ := authzUploadResource(t, orgAdmin, testOrg, bobUsername, "avatar", path, "", pngBytes())
	if resp.Status != "ok" {
		t.Fatalf("behavior regression: an org admin (niro-test/org-admin) could no longer edit another user's avatar in their own org: %s", resp.Msg)
	}

	var after struct {
		Status string `json:"status"`
		Data   struct {
			Avatar string `json:"avatar"`
		} `json:"data"`
	}
	authzGetJSON(t, nil, testTargetURL()+"/api/get-user?id="+testOrg+"/"+bobUsername, &after)
	if !strings.Contains(after.Data.Avatar, path) {
		t.Fatalf("behavior regression: org admin's avatar upload reported ok but bob's avatar was not updated (avatar=%q)", after.Data.Avatar)
	}
}

// TestUploadResource_RequiresAuthentication is the regression test for
// TC-73E66014: GetProviderFromContext must require a signed-in session even
// when the caller supplies a `provider` query parameter directly, instead of
// only enforcing sign-in on the fallback (no provider param) path.
func TestUploadResource_RequiresAuthentication(t *testing.T) {
	requireLiveTarget(t)

	anonymous := &http.Client{Timeout: 15 * time.Second}
	nonce := time.Now().UnixNano()

	// --- Negative control: anonymous upload WITHOUT provider=. Must be
	// rejected. Proves the target enforces sign-in on the ordinary path, so a
	// pass on the exploit below isn't an artifact of a broken environment. ---
	controlPath := fmt.Sprintf("anon-control-%d.txt", nonce)
	controlResp, _ := authzUploadResource(t, anonymous, "niro-test", "anonhax-regress", "", controlPath, "", []byte("control"))
	if controlResp.Status == "ok" {
		t.Fatalf("harness/environment problem: anonymous upload without provider= unexpectedly succeeded (%+v); cannot trust the exploit result below", *controlResp)
	}

	// --- Exploit: anonymous upload WITH provider=<known storage provider>. ---
	exploitPath := fmt.Sprintf("anon-exploit-%d.txt", nonce)
	exploitContent := fmt.Sprintf("anon upload content %d", nonce)
	exploitResp, _ := authzUploadResource(t, anonymous, "niro-test", "anonhax-regress", "", exploitPath, testStorageProvider, []byte(exploitContent))

	if exploitResp.Status == "ok" {
		fileURL, _ := exploitResp.Data.(string)
		t.Fatalf("invariant violated: an unauthenticated caller uploaded a file by supplying provider=%s directly "+
			"(response=%+v, served at %s)", testStorageProvider, *exploitResp, fileURL)
	}
}

func pngBytes() []byte {
	// Minimal valid 1x1 PNG.
	return []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
		0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41,
		0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
		0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xdd, 0x8d,
		0xb0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
		0x44, 0xae, 0x42, 0x60, 0x82,
	}
}
