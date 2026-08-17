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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

// Invariant under test (TC-F40531EB): CAS single sign-on login (POST
// /api/login, type=cas) must only issue a service ticket for a "service" URL
// that is on the target application's registered redirect-URI allow list,
// exactly like the pre-login check (GET /api/get-app-login, type=cas) already
// enforces via object.CheckCasLogin.

var casTestInitApp sync.Once

// casBootApp brings up enough of the real Casdoor server (DB + routes + authz
// policy) in-process to exercise the actual HTTP handlers for POST /api/login
// and GET /api/get-app-login, exactly as they run in production. It mirrors
// the relevant subset of main.go's startup sequence.
func casBootApp(t *testing.T) *httptest.Server {
	t.Helper()

	casTestInitApp.Do(func() {
		// Mirror main.go's session setup, using the in-memory provider so
		// the test has no filesystem/Redis dependency. Must happen before
		// web.InitBeegoBeforeTest below, which is what actually wires up
		// beego's session manager (registerSession hook).
		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.BConfig.WebConfig.Session.SessionProviderConfig = ""
		web.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24 * 30
		web.BConfig.WebConfig.Session.SessionGCMaxLifetime = int64(3600 * 24 * 30)

		// web.InitBeegoBeforeTest is beego's own test bootstrap: it loads
		// the app config and runs the same startup hooks that web.Run()
		// would (session/mime/template/admin/gzip). Using httptest against
		// web.BeeApp.Handlers directly (below) skips web.Run(), so this is
		// required or the session manager stays nil.
		web.InitBeegoBeforeTest("../conf/app.conf")

		object.InitAdapter() // connects to the DB configured in ../conf/app.conf
		object.CreateTables()
		object.InitDb()          // idempotent: seeds the built-in org/user/model/enforcer if missing
		authz.InitApi()          // (re)loads the built-in casbin policy, including "POST /api/login" for "*"
		object.InitUserManager() // wires up the user/group casbin enforcer used by DeleteUser during cleanup
		routers.InitAPI()        // registers all routes, including /api/login and /api/get-app-login
	})

	return httptest.NewServer(web.BeeApp.Handlers)
}

type casApiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func casNewHTTPClient(withJar bool) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if withJar {
		jar, _ := cookiejar.New(nil)
		c.Jar = jar
	}
	return c
}

func casDoGet(t *testing.T, client *http.Client, url string) casApiResponse {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out casApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

func casDoPostJSON(t *testing.T, client *http.Client, url string, body map[string]interface{}) casApiResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out casApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

// casTestFixture seeds a throwaway organization, application (with a single
// registered, non-localhost redirect URI so the app-configured allow list --
// not the built-in localhost/127.0.0.1 developer-origin bypass in
// util.IsValidOrigin -- is what's actually exercised), and a standard user.
type casTestFixture struct {
	Owner           string
	AppName         string
	Username        string
	Password        string
	RegisteredURI   string
	UnregisteredURI string
}

func setupCasFixture(t *testing.T) casTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner := "sec-test-org-" + suffix
	appName := "sec-test-app-" + suffix
	username := "cas-user"
	password := "NiroTestPass123!"
	registeredURI := "https://app-registered.example.test/callback"
	unregisteredURI := "https://evil.example.test/harvest"

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
		Providers:           []*object.ProviderItem{}, // no captcha provider wired up -> captcha check is skipped
		RedirectUris:        []string{registeredURI},
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
		DisplayName:       "CAS Test User",
		Email:             "cas-user-" + suffix + "@example.com",
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

	return casTestFixture{
		Owner:           owner,
		AppName:         appName,
		Username:        username,
		Password:        password,
		RegisteredURI:   registeredURI,
		UnregisteredURI: unregisteredURI,
	}
}

func casLoginBody(fx casTestFixture) map[string]interface{} {
	return map[string]interface{}{
		"application":  fx.AppName,
		"organization": fx.Owner,
		"username":     fx.Username,
		"password":     fx.Password,
		"signinMethod": "Password",
		"type":         "cas",
		"autoSignin":   true,
	}
}

// TestCasLoginRejectsUnregisteredService is the regression test for
// TC-F40531EB. It must fail (red) on the unfixed controllers/auth.go, where
// HandleLoggedIn's ResponseTypeCas branch calls object.GenerateCasToken(userId,
// service) directly without checking the service URL against the
// application's registered redirect-URI allow list -- unlike the pre-login
// informational endpoint (GET /api/get-app-login, type=cas), which correctly
// rejects the same unregistered URL via object.CheckCasLogin.
func TestCasLoginRejectsUnregisteredService(t *testing.T) {
	server := casBootApp(t)
	defer server.Close()

	fx := setupCasFixture(t)

	// Positive control: the pre-login informational check already enforces
	// the allow list for this exact unregistered service URL. This proves
	// the fixture/environment is healthy (a real application record with a
	// real allow list) before we exercise the vulnerable path below.
	preLoginURL := fmt.Sprintf("%s/api/get-app-login?type=cas&id=admin/%s&redirectUri=%s", server.URL, fx.AppName, fx.UnregisteredURI)
	preLoginResp := casDoGet(t, casNewHTTPClient(false), preLoginURL)
	if preLoginResp.Status != "error" {
		t.Fatalf("SETUP FAILURE: pre-login check (GET /api/get-app-login) did not reject the unregistered redirect URI as expected: status=%s msg=%s", preLoginResp.Status, preLoginResp.Msg)
	}

	// Vulnerable path: perform the actual CAS login (POST /api/login,
	// type=cas) against the same unregistered service URL. Per the
	// invariant, ticket issuance must be rejected exactly like the pre-login
	// check above -- not silently mint a service ticket.
	attacker := casNewHTTPClient(true)
	loginURL := fmt.Sprintf("%s/api/login?service=%s", server.URL, fx.UnregisteredURI)
	attackResp := casDoPostJSON(t, attacker, loginURL, casLoginBody(fx))

	if attackResp.Status == "ok" {
		t.Fatalf("invariant violated: CAS login issued a service ticket for an unregistered service URL: service=%s ticket=%s", fx.UnregisteredURI, string(attackResp.Data))
	}

	// The legitimate path -- CAS login against the REGISTERED redirect URI
	// -- must still succeed and return a real service ticket. This is the
	// control that proves the fix does not break normal CAS login.
	legit := casNewHTTPClient(true)
	controlURL := fmt.Sprintf("%s/api/login?service=%s", server.URL, fx.RegisteredURI)
	controlResp := casDoPostJSON(t, legit, controlURL, casLoginBody(fx))

	if controlResp.Status != "ok" {
		t.Fatalf("regression: CAS login against the REGISTERED redirect URI stopped succeeding: status=%s msg=%s", controlResp.Status, controlResp.Msg)
	}
	var ticket string
	if err := json.Unmarshal(controlResp.Data, &ticket); err != nil || !strings.HasPrefix(ticket, "ST-") {
		t.Fatalf("regression: CAS login against the REGISTERED redirect URI did not return a real service ticket: data=%s", controlResp.Data)
	}
}
