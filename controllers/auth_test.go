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

// Invariant under test (TC-D602262E): a user must not be able to sign in
// through an application that is configured for a DIFFERENT organization
// than the one the user belongs to -- an application's login must be
// restricted to members of its own organization.

var initAuthTestApp sync.Once

// bootAuthTestApp brings up enough of the real Casdoor server (DB + routes +
// authz policy) in-process to exercise the actual HTTP handler for
// POST /api/login and GET /api/get-account, exactly as they run in
// production. It mirrors the relevant subset of main.go's startup sequence.
// (Self-contained rather than shared with other _test.go files in this
// package, since those live on independent, not-yet-merged branches.)
func bootAuthTestApp(t *testing.T) *httptest.Server {
	t.Helper()

	initAuthTestApp.Do(func() {
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

type authTestAPIResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func authTestNewHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Timeout: 15 * time.Second, Jar: jar}
}

func authTestPostJSON(t *testing.T, client *http.Client, url string, body map[string]interface{}) authTestAPIResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out authTestAPIResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

func authTestGet(t *testing.T, client *http.Client, url string) authTestAPIResponse {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out authTestAPIResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

// authTestAccountIdentity pulls just owner/name out of a get-account
// response's Data payload, for compact, secret-free failure messages
// (the full payload carries a live accessToken JWT).
type authTestAccountIdentity struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func authTestExtractIdentity(resp authTestAPIResponse) authTestAccountIdentity {
	var id authTestAccountIdentity
	if len(resp.Data) > 0 {
		_ = json.Unmarshal(resp.Data, &id)
	}
	return id
}

// crossOrgLoginFixture seeds two throwaway organizations, one non-shared
// (IsShared=false) application per organization, and one standard user per
// organization -- mirroring the niro-alpha / niro-beta tenant-isolation
// pair used by the PoC for this finding.
type crossOrgLoginFixture struct {
	OrgA     string
	AppAName string
	UserA    string
	PassA    string

	OrgB     string
	AppBName string
	UserB    string
	PassB    string
}

func setupCrossOrgLoginFixture(t *testing.T) crossOrgLoginFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := "sec-test-org-a-" + suffix
	orgB := "sec-test-org-b-" + suffix
	appAName := "sec-test-app-a-" + suffix
	appBName := "sec-test-app-b-" + suffix
	userA := "alice-" + suffix
	userB := "bob-" + suffix
	pass := "NiroTestPass123!"

	makeOrg := func(name string) *object.Organization {
		return &object.Organization{
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
	}

	// makeApp builds a non-shared (IsShared defaults to false) application
	// scoped to org, matching app-niro-alpha/app-niro-beta from the PoC:
	// password login enabled, no captcha provider wired up.
	makeApp := func(name, org string) *object.Application {
		return &object.Application{
			Owner:               "admin",
			Name:                name,
			CreatedTime:         time.Now().Format(time.RFC3339),
			DisplayName:         "Security Test App " + name,
			Organization:        org,
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
	}

	makeUser := func(name, org, appName string) *object.User {
		return &object.User{
			Owner:             org,
			Name:              name,
			CreatedTime:       time.Now().Format(time.RFC3339),
			Type:              "normal-user",
			Password:          pass,
			DisplayName:       "Standard User " + name,
			Email:             name + "@example.com",
			SignupApplication: appName,
			CreatedIp:         "127.0.0.1",
		}
	}

	orgAObj := makeOrg(orgA)
	orgBObj := makeOrg(orgB)
	if _, err := object.AddOrganization(orgAObj); err != nil {
		t.Fatalf("failed to create test organization A: %v", err)
	}
	if _, err := object.AddOrganization(orgBObj); err != nil {
		t.Fatalf("failed to create test organization B: %v", err)
	}

	appAObj := makeApp(appAName, orgA)
	appBObj := makeApp(appBName, orgB)
	if _, err := object.AddApplication(appAObj); err != nil {
		t.Fatalf("failed to create test application A: %v", err)
	}
	if _, err := object.AddApplication(appBObj); err != nil {
		t.Fatalf("failed to create test application B: %v", err)
	}

	userAObj := makeUser(userA, orgA, appAName)
	userBObj := makeUser(userB, orgB, appBName)
	if _, err := object.AddUser(userAObj, "en"); err != nil {
		t.Fatalf("failed to create test user A: %v", err)
	}
	if _, err := object.AddUser(userBObj, "en"); err != nil {
		t.Fatalf("failed to create test user B: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteUser(userAObj)
		_, _ = object.DeleteUser(userBObj)
		_, _ = object.DeleteApplication(appAObj)
		_, _ = object.DeleteApplication(appBObj)
		_, _ = object.DeleteOrganization(orgAObj)
		_, _ = object.DeleteOrganization(orgBObj)
	})

	return crossOrgLoginFixture{
		OrgA: orgA, AppAName: appAName, UserA: userA, PassA: pass,
		OrgB: orgB, AppBName: appBName, UserB: userB, PassB: pass,
	}
}

// TestLoginRejectsCrossOrganizationApplication is the regression test for
// TC-D602262E. It must fail (red) on the unfixed controllers/auth.go, where
// the password branch of Login() calls object.CheckUserPassword using the
// client-supplied authForm.Organization without ever checking it against
// application.Organization, letting a user from one organization obtain a
// live session through an application exclusively provisioned for another.
func TestLoginRejectsCrossOrganizationApplication(t *testing.T) {
	server := bootAuthTestApp(t)
	defer server.Close()

	fx := setupCrossOrgLoginFixture(t)

	// Positive control: userA (org A) logs in through app A, which IS
	// provisioned for her own organization. This must succeed -- it proves
	// the fixture/environment is healthy, so a failure below in the exploit
	// case is provably the invariant, not a broken setup.
	controlClient := authTestNewHTTPClient()
	controlResp := authTestPostJSON(t, controlClient, server.URL+"/api/login", map[string]interface{}{
		"application":  fx.AppAName,
		"organization": fx.OrgA,
		"username":     fx.UserA,
		"password":     fx.PassA,
		"signinMethod": "Password",
		"type":         "login",
	})
	if controlResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: expected userA to log in successfully through her own org's application, got status=%q msg=%q", controlResp.Status, controlResp.Msg)
	}
	controlAccount := authTestGet(t, controlClient, server.URL+"/api/get-account")
	if controlAccount.Status != "ok" {
		t.Fatalf("SETUP FAILURE: expected an authenticated get-account response for userA, got status=%q msg=%q", controlAccount.Status, controlAccount.Msg)
	}

	// Exploit: userB belongs ONLY to org B. She logs in through app A (owned
	// exclusively by org A, IsShared=false) by passing her real org B
	// organization/credentials. The invariant requires this to be rejected.
	exploitClient := authTestNewHTTPClient()
	exploitResp := authTestPostJSON(t, exploitClient, server.URL+"/api/login", map[string]interface{}{
		"application":  fx.AppAName,
		"organization": fx.OrgB,
		"username":     fx.UserB,
		"password":     fx.PassB,
		"signinMethod": "Password",
		"type":         "login",
	})
	if exploitResp.Status == "ok" {
		exploitAccount := authTestGet(t, exploitClient, server.URL+"/api/get-account")
		id := authTestExtractIdentity(exploitAccount)
		t.Fatalf("INVARIANT VIOLATED: userB (organization %s) logged in through an application exclusively provisioned for organization %s (IsShared=false) and obtained a live session: get-account status=%q owner=%q name=%q",
			fx.OrgB, fx.OrgA, exploitAccount.Status, id.Owner, id.Name)
	}

	// Reverse direction, matching the PoC: userA (org A) must likewise be
	// rejected when logging in through org B's application.
	reverseClient := authTestNewHTTPClient()
	reverseResp := authTestPostJSON(t, reverseClient, server.URL+"/api/login", map[string]interface{}{
		"application":  fx.AppBName,
		"organization": fx.OrgA,
		"username":     fx.UserA,
		"password":     fx.PassA,
		"signinMethod": "Password",
		"type":         "login",
	})
	if reverseResp.Status == "ok" {
		reverseAccount := authTestGet(t, reverseClient, server.URL+"/api/get-account")
		id := authTestExtractIdentity(reverseAccount)
		t.Fatalf("INVARIANT VIOLATED (reverse direction): userA (organization %s) logged in through an application exclusively provisioned for organization %s (IsShared=false) and obtained a live session: get-account status=%q owner=%q name=%q",
			fx.OrgA, fx.OrgB, reverseAccount.Status, id.Owner, id.Name)
	}
}

// TestLoginAllowsOwnOrganizationMembersAfterFix proves the fix does not
// break the legitimate case: a user logging in through the application that
// actually belongs to their own organization must keep working, for both
// organizations in the fixture.
func TestLoginAllowsOwnOrganizationMembersAfterFix(t *testing.T) {
	server := bootAuthTestApp(t)
	defer server.Close()

	fx := setupCrossOrgLoginFixture(t)

	clientA := authTestNewHTTPClient()
	respA := authTestPostJSON(t, clientA, server.URL+"/api/login", map[string]interface{}{
		"application":  fx.AppAName,
		"organization": fx.OrgA,
		"username":     fx.UserA,
		"password":     fx.PassA,
		"signinMethod": "Password",
		"type":         "login",
	})
	if respA.Status != "ok" {
		t.Fatalf("behavior regression: userA could no longer log in through her own org's application: status=%q msg=%q", respA.Status, respA.Msg)
	}
	accountA := authTestGet(t, clientA, server.URL+"/api/get-account")
	if accountA.Status != "ok" {
		t.Fatalf("behavior regression: get-account failed for userA after a successful same-org login: status=%q msg=%q", accountA.Status, accountA.Msg)
	}

	clientB := authTestNewHTTPClient()
	respB := authTestPostJSON(t, clientB, server.URL+"/api/login", map[string]interface{}{
		"application":  fx.AppBName,
		"organization": fx.OrgB,
		"username":     fx.UserB,
		"password":     fx.PassB,
		"signinMethod": "Password",
		"type":         "login",
	})
	if respB.Status != "ok" {
		t.Fatalf("behavior regression: userB could no longer log in through her own org's application: status=%q msg=%q", respB.Status, respB.Msg)
	}
	accountB := authTestGet(t, clientB, server.URL+"/api/get-account")
	if accountB.Status != "ok" {
		t.Fatalf("behavior regression: get-account failed for userB after a successful same-org login: status=%q msg=%q", accountB.Status, accountB.Msg)
	}
}
