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
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

// Invariant under test (TC-7D66E27D): the session identifier a client holds
// BEFORE signing in must not remain valid as the AUTHENTICATED session
// identifier after a successful login; POST /api/login must issue a fresh
// session id on authentication (session fixation).

var initSessionFixationApp sync.Once

// bootSessionFixationApp brings up enough of the real Casdoor server (DB +
// routes + authz policy) in-process to exercise the actual HTTP handlers for
// POST /api/login and GET /api/get-account, exactly as they run in
// production. It mirrors the relevant subset of main.go's startup sequence.
func bootSessionFixationApp(t *testing.T) *httptest.Server {
	t.Helper()

	initSessionFixationApp.Do(func() {
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

type sessionFixationResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func sfDoGet(t *testing.T, client *http.Client, rawURL string) sessionFixationResponse {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s failed: %v", rawURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out sessionFixationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", rawURL, err, raw)
	}
	return out
}

func sfDoPostJSON(t *testing.T, client *http.Client, rawURL string, body map[string]interface{}) sessionFixationResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(rawURL, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", rawURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out sessionFixationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", rawURL, err, raw)
	}
	return out
}

// setupAuthFixture seeds a throwaway organization, password-enabled
// application, and normal user for exercising POST /api/login end to end.
func setupAuthFixture(t *testing.T) (owner, appName, username, password string) {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner = "sec-test-org-fx-" + suffix
	appName = "sec-test-app-fx-" + suffix
	username = "alice"
	password = "NiroTestPass123!"

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

	user := &object.User{
		Owner:             owner,
		Name:              username,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          password,
		DisplayName:       "Alice",
		Email:             "alice-" + suffix + "@example.com",
		SignupApplication: appName,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(user, "en"); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteUser(user)
		_, _ = object.DeleteApplication(app)
		_, _ = object.DeleteOrganization(org)
	})

	return owner, appName, username, password
}

func newJarClient(t *testing.T) (*http.Client, *cookiejar.Jar) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 15 * time.Second}, jar
}

func sessionCookieValue(t *testing.T, jar *cookiejar.Jar, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("bad url %q: %v", rawURL, err)
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == "casdoor_session_id" {
			return c.Value
		}
	}
	return ""
}

// TestLoginRotatesSessionID is the regression test for TC-7D66E27D. It must
// fail (red) on the unfixed code, where controllers/auth.go's Login()
// ResponseTypeLogin branch calls c.SetSessionUsername(userId) without first
// rotating the session id, so a session id issued before authentication
// remains valid -- and fully authenticated -- after a successful login.
func TestLoginRotatesSessionID(t *testing.T) {
	server := bootSessionFixationApp(t)
	defer server.Close()

	owner, appName, username, password := setupAuthFixture(t)

	victimClient, victimJar := newJarClient(t)

	// Step 1: an unauthenticated caller (the victim, before signing in) is
	// issued a pre-auth session cookie.
	pre := sfDoGet(t, victimClient, server.URL+"/api/get-account")
	if pre.Status != "error" {
		t.Fatalf("SETUP FAILURE: expected unauthenticated get-account to fail, got: %+v", pre)
	}
	preSessionID := sessionCookieValue(t, victimJar, server.URL)
	if preSessionID == "" {
		t.Fatalf("SETUP FAILURE: no pre-auth casdoor_session_id cookie was issued")
	}

	// Step 2: the SAME cookie jar logs in -- exactly what a real browser
	// does; cookies are never cleared between the pre-auth request and login.
	loginResp := sfDoPostJSON(t, victimClient, server.URL+"/api/login", map[string]interface{}{
		"application":  appName,
		"organization": owner,
		"username":     username,
		"password":     password,
		"signinMethod": "Password",
		"type":         "login",
	})
	if loginResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: login failed: %s", loginResp.Msg)
	}
	postSessionID := sessionCookieValue(t, victimJar, server.URL)

	// Positive control: a brand-new, cookie-less client must not be
	// authenticated -- proves the environment/harness is healthy, so a
	// failure below is specific to fixation, not a broken setup.
	controlClient, _ := newJarClient(t)
	controlResp := sfDoGet(t, controlClient, server.URL+"/api/get-account")
	if controlResp.Status != "error" {
		t.Fatalf("SETUP FAILURE: positive control failed -- a brand-new session should not be authenticated: %+v", controlResp)
	}

	// The attack: an independent jar seeded ONLY with the pre-auth session id
	// captured in step 1 (simulating an attacker who fixated that value on
	// the victim's browser before login, and who never learned the victim's
	// password) must NOT be authenticated after the victim logs in.
	attackerClient, attackerJar := newJarClient(t)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("bad server url: %v", err)
	}
	attackerJar.SetCookies(u, []*http.Cookie{{Name: "casdoor_session_id", Value: preSessionID}})
	attackerResp := sfDoGet(t, attackerClient, server.URL+"/api/get-account")

	if preSessionID == postSessionID {
		t.Errorf("invariant violated: session id was not rotated on login (still %s)", postSessionID)
	}
	if attackerResp.Status == "ok" {
		t.Errorf("invariant violated: attacker's jar, seeded only with the victim's pre-auth session id, is authenticated as %s after the victim logged in (session fixation)", username)
	}

	// The legitimate, freshly-issued post-login session must remain fully
	// authenticated -- the fix must not lock the real user out of their own
	// session.
	selfResp := sfDoGet(t, victimClient, server.URL+"/api/get-account")
	if selfResp.Status != "ok" {
		t.Fatalf("regression: the legitimate post-login session (using the rotated cookie) is no longer authenticated: %s", selfResp.Msg)
	}
}
