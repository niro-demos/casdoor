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

package controllers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

// Invariant under test (TC-E1F03605): an organization (tenant) administrator
// who is not the global administrator must not be able to obtain the
// literal, live session credential (the casdoor_session_id cookie value) of
// another user in their organization and use it to authenticate as that
// user without the user's password.

var initSessionApp sync.Once

// bootSessionApp brings up enough of the real Casdoor server (DB + routes +
// authz policy) in-process to exercise the actual HTTP handlers for
// GET/POST /api/get-sessions, /api/get-session, /api/delete-session,
// /api/login and /api/get-account, exactly as they run in production.
func bootSessionApp(t *testing.T) *httptest.Server {
	t.Helper()

	initSessionApp.Do(func() {
		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.BConfig.WebConfig.Session.SessionProviderConfig = ""
		web.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24 * 30
		web.BConfig.WebConfig.Session.SessionGCMaxLifetime = int64(3600 * 24 * 30)

		web.InitBeegoBeforeTest("../conf/app.conf")

		object.InitAdapter()
		object.CreateTables()
		object.InitDb()
		authz.InitApi()
		object.InitUserManager()
		routers.InitAPI()
	})

	return httptest.NewServer(web.BeeApp.Handlers)
}

type sessionApiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type sessionDTO struct {
	Owner       string   `json:"owner"`
	Name        string   `json:"name"`
	Application string   `json:"application"`
	SessionId   []string `json:"sessionId"`
}

type accountDTO struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func newSessionHTTPClient(withJar bool) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if withJar {
		jar, _ := cookiejar.New(nil)
		c.Jar = jar
	}
	return c
}

func sessionDoGet(t *testing.T, client *http.Client, url string) sessionApiResponse {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out sessionApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

func sessionDoPostJSON(t *testing.T, client *http.Client, url string, body map[string]interface{}) sessionApiResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out sessionApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

// sessionCookieValue extracts the literal casdoor_session_id cookie value a
// client is holding for base, i.e. exactly what Beego's session middleware
// will accept back as a live, authenticating credential.
func sessionCookieValue(client *http.Client, base string) string {
	u, _ := http.NewRequest(http.MethodGet, base, nil)
	if client.Jar == nil {
		return ""
	}
	for _, c := range client.Jar.Cookies(u.URL) {
		if c.Name == "casdoor_session_id" {
			return c.Value
		}
	}
	return ""
}

func getAccountWithCookie(t *testing.T, base string, cookieValue string) sessionApiResponse {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/get-account", nil)
	if cookieValue != "" {
		req.Header.Set("Cookie", "casdoor_session_id="+cookieValue)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/get-account failed: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out sessionApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from get-account: %v (body=%s)", err, raw)
	}
	return out
}

// sessionTestFixture seeds a throwaway organization, application, org-admin
// user, and one victim (ordinary) user, and returns a cleanup func.
type sessionTestFixture struct {
	Owner      string
	AdminName  string
	AdminPass  string
	VictimName string
	VictimPass string
	AppName    string
}

func setupSessionFixture(t *testing.T) sessionTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner := "sec-test-org-" + suffix
	appName := "sec-test-app-" + suffix
	adminName := "org-admin"
	adminPass := "NiroTestPass123!"
	victimName := "victim"
	victimPass := "NiroVictimPass123!"

	org := &object.Organization{
		Owner:           "admin",
		Name:            owner,
		CreatedTime:     time.Now().Format(time.RFC3339),
		DisplayName:     "Security Test Org " + suffix,
		PasswordType:    "plain",
		PasswordOptions: []string{"AtLeast6"},
		CountryCodes:    []string{"US"},
		Tags:            []string{},
		Languages:       []string{"en"},
		AccountItems:    object.GetDefaultAccountItems(),
	}
	if _, err := object.AddOrganization(org); err != nil {
		t.Fatalf("failed to create test organization: %v", err)
	}

	app := &object.Application{
		Owner:               "admin",
		Name:                appName,
		CreatedTime:         time.Now().Format(time.RFC3339),
		DisplayName:         "Security Test App " + suffix,
		Organization:        owner,
		Cert:                "cert-built-in",
		EnablePassword:      true,
		SigninMethods:       []*object.SigninMethod{{Name: "Password", DisplayName: "Password", Rule: "All"}},
		Providers:           []*object.ProviderItem{},
		RedirectUris:        []string{},
		Tags:                []string{},
		TokenFormat:         "JWT",
		TokenFields:         []string{},
		ExpireInHours:       168,
		FormOffset:          2,
		CookieExpireInHours: 720,
	}
	if _, err := object.AddApplication(app); err != nil {
		t.Fatalf("failed to create test application: %v", err)
	}

	admin := &object.User{
		Owner:             owner,
		Name:              adminName,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          adminPass,
		DisplayName:       "Org Admin",
		Email:             "org-admin-" + suffix + "@example.com",
		IsAdmin:           true,
		SignupApplication: appName,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(admin, "en"); err != nil {
		t.Fatalf("failed to create test org admin user: %v", err)
	}

	victim := &object.User{
		Owner:             owner,
		Name:              victimName,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          victimPass,
		DisplayName:       "Victim",
		Email:             "victim-" + suffix + "@example.com",
		IsAdmin:           false,
		SignupApplication: appName,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(victim, "en"); err != nil {
		t.Fatalf("failed to create test victim user: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteAllUserSessions(owner, adminName)
		_, _ = object.DeleteAllUserSessions(owner, victimName)
		_, _ = object.DeleteUser(admin)
		_, _ = object.DeleteUser(victim)
		_, _ = object.DeleteApplication(app)
		_, _ = object.DeleteOrganization(org)
	})

	return sessionTestFixture{
		Owner:      owner,
		AdminName:  adminName,
		AdminPass:  adminPass,
		VictimName: victimName,
		VictimPass: victimPass,
		AppName:    appName,
	}
}

func sessionLogin(t *testing.T, base string, client *http.Client, fx sessionTestFixture, username, password string) {
	t.Helper()
	resp := sessionDoPostJSON(t, client, base+"/api/login", map[string]interface{}{
		"username":     username,
		"password":     password,
		"organization": fx.Owner,
		"application":  fx.AppName,
		"signinMethod": "Password",
		"type":         "login",
	})
	if resp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: login for %s failed: %s", username, resp.Msg)
	}
}

// findVictimSession locates the victim's entry in a GetSessions response.
func findVictimSession(t *testing.T, resp sessionApiResponse, fx sessionTestFixture) *sessionDTO {
	t.Helper()
	if resp.Status != "ok" {
		t.Fatalf("get-sessions failed: %s", resp.Msg)
	}
	var sessions []sessionDTO
	if len(resp.Data) > 0 && string(resp.Data) != "null" {
		if err := json.Unmarshal(resp.Data, &sessions); err != nil {
			t.Fatalf("bad sessions payload: %v (data=%s)", err, resp.Data)
		}
	}
	for i := range sessions {
		if sessions[i].Owner == fx.Owner && sessions[i].Name == fx.VictimName {
			return &sessions[i]
		}
	}
	return nil
}

// TestGetSessionsDoesNotExposeReplayableSessionId is the regression test for
// TC-E1F03605. It must fail (red) on the unfixed controllers/session.go,
// where GetSessions() serializes object.Session.SessionId verbatim: the
// literal, live Beego session-store id captured at login, which can be
// replayed as a casdoor_session_id cookie to fully authenticate as the
// victim without their password.
func TestGetSessionsDoesNotExposeReplayableSessionId(t *testing.T) {
	server := bootSessionApp(t)
	defer server.Close()

	fx := setupSessionFixture(t)

	// Victim logs in, capturing her live, literal session credential exactly
	// as her browser would hold it.
	victimClient := newSessionHTTPClient(true)
	sessionLogin(t, server.URL, victimClient, fx, fx.VictimName, fx.VictimPass)
	victimLiteralCookie := sessionCookieValue(victimClient, server.URL)
	if victimLiteralCookie == "" {
		t.Fatalf("SETUP FAILURE: could not capture victim's casdoor_session_id cookie after login")
	}

	// Positive control: a brand-new, cookie-less client is rejected by
	// /api/get-account -- proves the environment itself requires
	// authentication, isolating the vulnerability below from a broken setup.
	control := getAccountWithCookie(t, server.URL, "")
	if control.Status == "ok" {
		t.Fatalf("SETUP FAILURE: unauthenticated /api/get-account returned ok with no cookie at all")
	}

	// Org admin (not global admin) logs in and lists her org's sessions --
	// an operation the app intentionally allows (authz/authz.go IsAllowed).
	adminClient := newSessionHTTPClient(true)
	sessionLogin(t, server.URL, adminClient, fx, fx.AdminName, fx.AdminPass)

	resp := sessionDoGet(t, adminClient, fmt.Sprintf("%s/api/get-sessions?owner=%s", server.URL, fx.Owner))
	victimEntry := findVictimSession(t, resp, fx)
	if victimEntry == nil {
		t.Fatalf("SETUP FAILURE: org admin's get-sessions response did not include the victim's session at all")
	}
	if len(victimEntry.SessionId) == 0 {
		t.Fatalf("SETUP FAILURE: victim's session entry carries no sessionId values to check")
	}

	// Invariant: none of the values returned to the org admin may be the
	// victim's literal, live session credential.
	for _, sid := range victimEntry.SessionId {
		if sid == victimLiteralCookie {
			t.Fatalf("invariant violated: GET /api/get-sessions returned the victim's literal, live session id in cleartext: %q", sid)
		}
	}

	// Invariant, end-to-end: whatever value WAS returned must not
	// authenticate as the victim when replayed as a casdoor_session_id
	// cookie from a completely fresh, unauthenticated client.
	for _, sid := range victimEntry.SessionId {
		takeover := getAccountWithCookie(t, server.URL, sid)
		var acct accountDTO
		_ = json.Unmarshal(takeover.Data, &acct)
		if takeover.Status == "ok" && acct.Owner == fx.Owner && acct.Name == fx.VictimName {
			t.Fatalf("invariant violated: replaying get-sessions value %q as a cookie authenticated as the victim (%s/%s) with no password", sid, fx.Owner, fx.VictimName)
		}
	}

	// The victim's real, original cookie must still work for the victim
	// herself -- proving the fix redacts the API response, not the actual
	// live session.
	self := getAccountWithCookie(t, server.URL, victimLiteralCookie)
	var selfAcct accountDTO
	_ = json.Unmarshal(self.Data, &selfAcct)
	if self.Status != "ok" || selfAcct.Name != fx.VictimName {
		t.Fatalf("regression: victim's own live session cookie stopped authenticating her: status=%s msg=%s", self.Status, self.Msg)
	}
}

// TestOrgAdminCanStillRevokeSpecificSession proves the fix does not break
// the legitimate session-management feature the org admin console
// (SessionListPage.js) relies on: an org admin must still be able to
// identify and revoke one specific live session of one of their org's
// members, using only whatever identifier the API itself returned.
func TestOrgAdminCanStillRevokeSpecificSession(t *testing.T) {
	server := bootSessionApp(t)
	defer server.Close()

	fx := setupSessionFixture(t)

	victimClient := newSessionHTTPClient(true)
	sessionLogin(t, server.URL, victimClient, fx, fx.VictimName, fx.VictimPass)
	victimLiteralCookie := sessionCookieValue(victimClient, server.URL)
	if victimLiteralCookie == "" {
		t.Fatalf("SETUP FAILURE: could not capture victim's casdoor_session_id cookie after login")
	}

	// Sanity: the victim's session authenticates her before revocation.
	before := getAccountWithCookie(t, server.URL, victimLiteralCookie)
	var beforeAcct accountDTO
	_ = json.Unmarshal(before.Data, &beforeAcct)
	if before.Status != "ok" || beforeAcct.Name != fx.VictimName {
		t.Fatalf("SETUP FAILURE: victim's session did not authenticate her before revocation: status=%s msg=%s", before.Status, before.Msg)
	}

	adminClient := newSessionHTTPClient(true)
	sessionLogin(t, server.URL, adminClient, fx, fx.AdminName, fx.AdminPass)

	resp := sessionDoGet(t, adminClient, fmt.Sprintf("%s/api/get-sessions?owner=%s", server.URL, fx.Owner))
	victimEntry := findVictimSession(t, resp, fx)
	if victimEntry == nil || len(victimEntry.SessionId) == 0 {
		t.Fatalf("SETUP FAILURE: could not find victim's session entry to revoke")
	}
	displayedId := victimEntry.SessionId[0]

	deleteURL := fmt.Sprintf("%s/api/delete-session?sessionId=%s", server.URL, displayedId)
	deleteResp := sessionDoPostJSON(t, adminClient, deleteURL, map[string]interface{}{
		"owner":       fx.Owner,
		"name":        fx.VictimName,
		"application": fx.AppName,
	})
	if deleteResp.Status != "ok" {
		t.Fatalf("behavior regression: org admin could not revoke the victim's session using the identifier the API returned: status=%s msg=%s", deleteResp.Status, deleteResp.Msg)
	}

	// The record the admin targeted (identified only by what the API
	// displayed, never by the literal live id) must actually be gone: a
	// fresh listing must no longer show that session entry for the victim.
	// (Note: whether the underlying Beego cookie itself also stops working
	// is a separate, pre-existing behavior gated on owner/application ==
	// the built-in org/app in object.DeleteSessionId -- unrelated to this
	// fix and unchanged by it, so it is not asserted here.)
	afterResp := sessionDoGet(t, adminClient, fmt.Sprintf("%s/api/get-sessions?owner=%s", server.URL, fx.Owner))
	afterEntry := findVictimSession(t, afterResp, fx)
	if afterEntry != nil {
		for _, sid := range afterEntry.SessionId {
			if sid == displayedId {
				t.Fatalf("behavior regression: the session entry the org admin revoked via the displayed identifier %q is still present after deletion", displayedId)
			}
		}
	}
}
