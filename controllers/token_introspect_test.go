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

// Invariant under test (TC-DB858719): the token introspection endpoint
// (POST /api/login/oauth/introspect) must only reveal a token's metadata to
// the OAuth client the token was issued for, not to any other registered
// client in the system -- including a client that belongs to a completely
// different organization/tenant.

var initIntrospectApp sync.Once

// bootApp brings up enough of the real Casdoor server (DB + routes + authz
// policy) in-process to exercise the actual HTTP handlers for /api/login,
// /api/login/oauth/access_token and /api/login/oauth/introspect, exactly as
// they run in production. It mirrors the relevant subset of main.go's
// startup sequence.
func bootApp(t *testing.T) *httptest.Server {
	t.Helper()

	initIntrospectApp.Do(func() {
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

type apiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func doPostJSON(t *testing.T, client *http.Client, url string, body map[string]interface{}) apiResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out apiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

type introspectionDTO struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	ClientId string `json:"client_id"`
	Username string `json:"username"`
	Sub      string `json:"sub"`
	Jti      string `json:"jti"`
}

// introspectTestFixture seeds two independent organizations, each with its
// own OAuth application (and its own generated client_id/client_secret), and
// a standard user that belongs only to the "alpha" organization.
type introspectTestFixture struct {
	AlphaOrgName      string
	AlphaAppName      string
	AlphaClientId     string
	AlphaClientSecret string
	BetaOrgName       string
	BetaAppName       string
	BetaClientId      string
	BetaClientSecret  string
	BobUsername       string
	BobPassword       string
	RedirectUri       string
}

func setupIntrospectFixture(t *testing.T) introspectTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	redirectUri := "http://localhost:19001/callback"

	newOrg := func(name string) *object.Organization {
		org := &object.Organization{
			Owner:           "admin",
			Name:            name,
			CreatedTime:     time.Now().Format(time.RFC3339),
			DisplayName:     "Security Test Org " + name,
			PasswordType:    "plain",
			PasswordOptions: []string{"AtLeast6"},
			CountryCodes:    []string{"US"},
			Tags:            []string{},
			Languages:       []string{"en"},
			AccountItems:    object.GetDefaultAccountItems(),
		}
		if _, err := object.AddOrganization(org); err != nil {
			t.Fatalf("failed to create test organization %s: %v", name, err)
		}
		return org
	}

	newApp := func(name, orgName string) *object.Application {
		app := &object.Application{
			Owner:               "admin",
			Name:                name,
			CreatedTime:         time.Now().Format(time.RFC3339),
			DisplayName:         "Security Test App " + name,
			Organization:        orgName,
			EnablePassword:      true,
			SigninMethods:       []*object.SigninMethod{{Name: "Password", DisplayName: "Password", Rule: "All"}},
			Providers:           []*object.ProviderItem{},
			RedirectUris:        []string{redirectUri},
			Tags:                []string{},
			TokenFormat:         "JWT",
			TokenFields:         []string{},
			ExpireInHours:       168,
			FormOffset:          2,
			CookieExpireInHours: 720,
		}
		if _, err := object.AddApplication(app); err != nil {
			t.Fatalf("failed to create test application %s: %v", name, err)
		}
		return app
	}

	alphaOrgName := "niro-alpha-" + suffix
	betaOrgName := "niro-beta-" + suffix
	alphaAppName := "app-niro-alpha-" + suffix
	betaAppName := "app-niro-beta-" + suffix

	alphaOrg := newOrg(alphaOrgName)
	betaOrg := newOrg(betaOrgName)
	alphaApp := newApp(alphaAppName, alphaOrgName)
	betaApp := newApp(betaAppName, betaOrgName)

	bobPassword := "NiroTestPass123!"
	bob := &object.User{
		Owner:             alphaOrgName,
		Name:              "bob",
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          bobPassword,
		DisplayName:       "Bob",
		Email:             "bob-" + suffix + "@example.com",
		SignupApplication: alphaAppName,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(bob, "en"); err != nil {
		t.Fatalf("failed to create test user bob: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteUser(bob)
		_, _ = object.DeleteApplication(alphaApp)
		_, _ = object.DeleteApplication(betaApp)
		_, _ = object.DeleteOrganization(alphaOrg)
		_, _ = object.DeleteOrganization(betaOrg)
	})

	return introspectTestFixture{
		AlphaOrgName:      alphaOrgName,
		AlphaAppName:      alphaAppName,
		AlphaClientId:     alphaApp.ClientId,
		AlphaClientSecret: alphaApp.ClientSecret,
		BetaOrgName:       betaOrgName,
		BetaAppName:       betaAppName,
		BetaClientId:      betaApp.ClientId,
		BetaClientSecret:  betaApp.ClientSecret,
		BobUsername:       "bob",
		BobPassword:       bobPassword,
		RedirectUri:       redirectUri,
	}
}

// obtainAuthorizationCodeToken runs the standard authorization_code flow as
// fx's user against the alpha application and returns the resulting
// access_token, whose owning application/aud is app-niro-alpha only.
func obtainAuthorizationCodeToken(t *testing.T, server *httptest.Server, fx introspectTestFixture) string {
	t.Helper()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}

	loginURL := fmt.Sprintf("%s/api/login?clientId=%s&responseType=code&redirectUri=%s&scope=openid+profile+email&state=xyz",
		server.URL, url.QueryEscape(fx.AlphaClientId), url.QueryEscape(fx.RedirectUri))
	loginResp := doPostJSON(t, client, loginURL, map[string]interface{}{
		"application":  fx.AlphaAppName,
		"organization": fx.AlphaOrgName,
		"username":     fx.BobUsername,
		"password":     fx.BobPassword,
		"type":         "code",
		"signinMethod": "Password",
	})
	if loginResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: bob code login against app-niro-alpha failed: %s", loginResp.Msg)
	}
	var code string
	if err := json.Unmarshal(loginResp.Data, &code); err != nil || code == "" {
		t.Fatalf("SETUP FAILURE: could not extract authorization code: %v (data=%s)", err, loginResp.Data)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", fx.AlphaClientId)
	form.Set("client_secret", fx.AlphaClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", fx.RedirectUri)
	resp, err := http.PostForm(server.URL+"/api/login/oauth/access_token", form)
	if err != nil {
		t.Fatalf("SETUP FAILURE: token exchange request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("SETUP FAILURE: could not exchange code for access_token: %v (body=%s)", err, body)
	}
	return tok.AccessToken
}

func introspectAs(t *testing.T, server *httptest.Server, token, clientId, clientSecret string) introspectionDTO {
	t.Helper()

	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", clientId)
	form.Set("client_secret", clientSecret)
	resp, err := http.PostForm(server.URL+"/api/login/oauth/introspect", form)
	if err != nil {
		t.Fatalf("introspect request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out introspectionDTO
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("bad introspection JSON: %v (body=%s)", err, body)
	}
	return out
}

// TestIntrospectTokenRejectsUnrelatedApplication is the regression test for
// TC-DB858719. It must fail (red) on the unfixed controllers/token.go,
// where IntrospectToken() never compares the token's actual owning
// application against the application the caller authenticated as, so any
// registered OAuth client can read the full metadata (active state,
// username, sub, scope, jti, ...) of a token issued to a completely
// unrelated application in another organization.
func TestIntrospectTokenRejectsUnrelatedApplication(t *testing.T) {
	server := bootApp(t)
	defer server.Close()

	fx := setupIntrospectFixture(t)
	token := obtainAuthorizationCodeToken(t, server, fx)

	// Positive control: the token's real owner (app-niro-alpha) introspects
	// its own token using its own credentials. This must succeed and return
	// bob's real claims -- it proves the environment/endpoint is healthy,
	// isolating the vulnerable path below.
	control := introspectAs(t, server, token, fx.AlphaClientId, fx.AlphaClientSecret)
	if !control.Active || control.Username != fx.BobUsername {
		t.Fatalf("SETUP FAILURE: positive control failed -- environment is unhealthy, cannot conclude anything about the attack step: %+v", control)
	}

	// Attack: app-niro-beta -- a different, unrelated application in a
	// different organization -- introspects the SAME token using only its
	// own valid credentials. Per the invariant, this must return
	// {"active": false} and must not leak any of the token's real claims.
	attack := introspectAs(t, server, token, fx.BetaClientId, fx.BetaClientSecret)
	if attack.Active {
		t.Fatalf("invariant violated: app-niro-beta (unrelated application, different organization) received active=true and the real claims (username=%q sub=%q scope=%q jti=%q) for a token issued to app-niro-alpha/bob that it has no relationship to. Expected {\"active\": false}",
			attack.Username, attack.Sub, attack.Scope, attack.Jti)
	}
	if attack.Username != "" || attack.Sub != "" {
		t.Fatalf("invariant violated: app-niro-beta received token claims (username=%q sub=%q) despite active=false", attack.Username, attack.Sub)
	}
}
