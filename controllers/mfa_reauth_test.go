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

// This is a live, end-to-end regression test for the invariant behind
// TC-E5B67EE7: disabling a user's MFA must require the caller to re-prove
// their identity (their current password) when acting on their own account
// — an already-valid session cookie must not be enough on its own. The bug
// lives in the wiring between the authorization filter, the DeleteMfa
// controller and the object layer, not in any single pure function, so this
// test drives the real HTTP API of a running Casdoor instance rather than
// calling Go functions directly.
//
// It is opt-in: it needs a running Casdoor server, backed by a database the
// test process can also open directly (to set up and tear down its own
// fixtures — a throwaway organization/application/users, never the seeded
// data used by any pentest harness). Point it at both, e.g. against the
// niro harness's own throwaway SQLite database:
//
//	CASDOOR_MFA_REAUTH_TEST_URL=http://localhost:8000 \
//	driverName=sqlite \
//	dataSourceName="file:/path/to/niro/harness/run/data/casdoor.db?cache=shared" \
//	dbName=casdoor \
//	go test ./controllers/ -run TestDeleteMfaRequiresReauth -v
//
// Without a reachable server and database env vars it skips itself, so it
// never breaks a plain `go test ./...` run.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func mfaReauthTestTarget() string {
	target := os.Getenv("CASDOOR_MFA_REAUTH_TEST_URL")
	if target == "" {
		target = "http://localhost:8000"
	}
	return target
}

func mfaReauthTargetReachable(target string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target + "/api/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

// mfaReauthHTTPClient is a minimal session-cookie-carrying HTTP client used
// to drive the live API exactly like a real browser tab would.
type mfaReauthHTTPClient struct {
	target string
	hc     *http.Client
}

func newMfaReauthHTTPClient(target string) *mfaReauthHTTPClient {
	jar, _ := cookiejar.New(nil)
	return &mfaReauthHTTPClient{target: target, hc: &http.Client{Jar: jar, Timeout: 15 * time.Second}}
}

func (c *mfaReauthHTTPClient) postJSON(t *testing.T, path string, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal request body for %s: %v", path, err)
	}
	resp, err := c.hc.Post(c.target+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("request to %s failed: %v", path, err)
	}
	defer resp.Body.Close()
	return decodeMfaReauthResponse(t, path, resp)
}

func (c *mfaReauthHTTPClient) postForm(t *testing.T, path string, form url.Values) map[string]interface{} {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, c.target+path, bytes.NewReader([]byte(form.Encode())))
	if err != nil {
		t.Fatalf("failed to build request for %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatalf("request to %s failed: %v", path, err)
	}
	defer resp.Body.Close()
	return decodeMfaReauthResponse(t, path, resp)
}

func decodeMfaReauthResponse(t *testing.T, path string, resp *http.Response) map[string]interface{} {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body from %s: %v", path, err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("non-JSON response from %s (http %d): %s", path, resp.StatusCode, raw)
	}
	return out
}

// initMfaReauthTestAdapter opens the same database the target server is
// using, so the test can create and clean up its own fixtures directly.
// This intentionally mirrors only the minimal slice of object.InitConfig()
// needed to open the already-provisioned database (driverName /
// dataSourceName / dbName, read from the environment): the schema already
// exists (the running server created it), and object.InitFlag()'s
// flag.Parse() would collide with `go test`'s own flags if called here.
func initMfaReauthTestAdapter(t *testing.T) {
	t.Helper()
	object.InitAdapter()
	object.InitUserManager()
}

func TestDeleteMfaRequiresReauth(t *testing.T) {
	target := mfaReauthTestTarget()
	if !mfaReauthTargetReachable(target) {
		t.Skipf("no live Casdoor server reachable at %s (set CASDOOR_MFA_REAUTH_TEST_URL); skipping live regression test for TC-E5B67EE7", target)
	}
	if os.Getenv("driverName") == "" || os.Getenv("dataSourceName") == "" {
		t.Skip("driverName/dataSourceName env vars for the target's database are not set; skipping live regression test for TC-E5B67EE7")
	}

	initMfaReauthTestAdapter(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "niro-mfa-reauth-" + suffix
	appName := orgName + "-app"
	const (
		victimName    = "victim"
		adminName     = "supportadmin"
		victimPw      = "Victim-Test-Pw-1!"
		victimWrongPw = "not-the-password"
		adminPw       = "Admin-Test-Pw-1!"
		totpSecret    = "JBSWY3DPEHPK3PXP"
	)

	cleanup := func() {
		_, _ = object.DeleteUser(&object.User{Owner: orgName, Name: victimName})
		_, _ = object.DeleteUser(&object.User{Owner: orgName, Name: adminName})
		_, _ = object.DeleteApplication(&object.Application{Owner: "admin", Name: appName})
		_, _ = object.DeleteOrganization(&object.Organization{Owner: "admin", Name: orgName})
	}
	cleanup()
	t.Cleanup(cleanup)

	org := &object.Organization{
		Owner:        "admin",
		Name:         orgName,
		DisplayName:  orgName,
		PasswordType: "plain",
		CreatedTime:  util.GetCurrentTime(),
	}
	if ok, err := object.AddOrganization(org); err != nil || !ok {
		t.Fatalf("failed to create test organization: ok=%v err=%v", ok, err)
	}

	app := &object.Application{
		Owner:          "admin",
		Name:           appName,
		DisplayName:    appName,
		Organization:   orgName,
		EnablePassword: true,
		CreatedTime:    util.GetCurrentTime(),
	}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("failed to create test application: ok=%v err=%v", ok, err)
	}

	victim := &object.User{
		Owner:        orgName,
		Name:         victimName,
		CreatedTime:  util.GetCurrentTime(),
		Id:           util.GenerateId(),
		Type:         "normal-user",
		Password:     victimPw,
		PasswordType: "plain",
	}
	if ok, err := object.AddUser(victim, "en"); err != nil || !ok {
		t.Fatalf("failed to create victim user: ok=%v err=%v", ok, err)
	}

	// A same-org admin: a legitimate support workflow (e.g. resetting MFA
	// for a locked-out user) that must keep working after the fix, since
	// the admin cannot know the victim's password.
	admin := &object.User{
		Owner:        orgName,
		Name:         adminName,
		CreatedTime:  util.GetCurrentTime(),
		Id:           util.GenerateId(),
		Type:         "normal-user",
		Password:     adminPw,
		PasswordType: "plain",
		IsAdmin:      true,
	}
	if ok, err := object.AddUser(admin, "en"); err != nil || !ok {
		t.Fatalf("failed to create org-admin user: ok=%v err=%v", ok, err)
	}

	enrollMfa := func() {
		u, err := object.GetUser(util.GetId(orgName, victimName))
		if err != nil || u == nil {
			t.Fatalf("failed to load victim to enroll MFA: %v", err)
		}
		u.TotpSecret = totpSecret
		u.PreferredMfaType = object.TotpType
		if _, err := object.UpdateUser(u.GetId(), u, []string{"totp_secret", "preferred_mfa_type"}, true); err != nil {
			t.Fatalf("failed to enroll MFA for victim: %v", err)
		}
	}

	victimHasMfa := func() bool {
		u, err := object.GetUser(util.GetId(orgName, victimName))
		if err != nil || u == nil {
			t.Fatalf("failed to reload victim: %v", err)
		}
		return u.IsMfaEnabled() && u.TotpSecret != ""
	}

	login := func(username, password string) *mfaReauthHTTPClient {
		client := newMfaReauthHTTPClient(target)
		resp := client.postJSON(t, "/api/login", map[string]interface{}{
			"username":     username,
			"password":     password,
			"organization": orgName,
			"application":  appName,
			"type":         "login",
		})
		if resp["status"] != "ok" {
			t.Fatalf("login for %s failed: %v", username, resp)
		}
		return client
	}

	deleteMfa := func(client *mfaReauthHTTPClient, targetOwner, targetName, password string) map[string]interface{} {
		form := url.Values{
			"owner":   {targetOwner},
			"name":    {targetName},
			"mfaType": {object.TotpType},
		}
		if password != "" {
			form.Set("password", password)
		}
		return client.postForm(t, "/api/delete-mfa/", form)
	}

	// The victim logs in *before* MFA exists — establishing the very
	// session cookie the attack below will replay — and only enrolls MFA
	// afterwards, exactly like TC-E5B67EE7's PoC: a session opened before
	// MFA existed must not remain sufficient to strip MFA back off once it
	// does. (Enrolling MFA on an existing password-only session is normal:
	// checkMfaEnable() in the login flow only intercepts *future* logins,
	// not sessions already established.)
	victimSession := login(victimName, victimPw)

	enrollMfa()
	if !victimHasMfa() {
		t.Fatal("environment unhealthy: victim does not have MFA enrolled after setup, aborting")
	}

	// --- Attack: the victim's own (pre-MFA) session cookie alone, no password ---
	attackResp := deleteMfa(victimSession, orgName, victimName, "")
	if attackResp["status"] == "ok" {
		t.Fatalf("invariant violated: delete-mfa succeeded for the account owner using only the session cookie, no password proof; response=%v", attackResp)
	}
	if !victimHasMfa() {
		t.Fatal("invariant violated: victim's MFA was removed even though delete-mfa reported an error")
	}

	// --- Attack variant: a wrong password must also be rejected ---
	wrongPwResp := deleteMfa(victimSession, orgName, victimName, victimWrongPw)
	if wrongPwResp["status"] == "ok" {
		t.Fatalf("invariant violated: delete-mfa succeeded for the account owner with an incorrect password; response=%v", wrongPwResp)
	}
	if !victimHasMfa() {
		t.Fatal("invariant violated: victim's MFA was removed by a wrong-password request")
	}

	// --- Legitimate self-service: correct password must still work ---
	correctPwResp := deleteMfa(victimSession, orgName, victimName, victimPw)
	if correctPwResp["status"] != "ok" {
		t.Fatalf("self-service delete-mfa with the correct current password should succeed, got: %v", correctPwResp)
	}
	if victimHasMfa() {
		t.Fatal("delete-mfa reported success but victim's MFA is still enabled")
	}

	// --- Regression guard: an org admin resetting another user's MFA (a
	// legitimate support workflow) must keep working without that user's
	// password — they are already authorized by the existing owner-scoped
	// admin check, and cannot know the victim's password. ---
	enrollMfa()
	if !victimHasMfa() {
		t.Fatal("environment unhealthy: could not re-enroll MFA for the admin-reset scenario")
	}
	adminSession := login(adminName, adminPw)
	adminResetResp := deleteMfa(adminSession, orgName, victimName, "")
	if adminResetResp["status"] != "ok" {
		t.Fatalf("an org admin resetting another user's MFA should not require that user's password; response=%v", adminResetResp)
	}
	if victimHasMfa() {
		t.Fatal("admin-initiated delete-mfa reported success but victim's MFA is still enabled")
	}
}
