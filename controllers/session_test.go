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

// Invariant under test (TC-EDF8A1C1): only an organization admin or the
// global admin may add, update, or delete entries in the server-side
// session-tracking table (/api/add-session, /api/update-session,
// /api/delete-session). An ordinary logged-in user must not be able to
// write to this admin-only API, even for their own record.

var initSessionApp sync.Once

// bootSessionApp brings up enough of the real Casdoor server (DB + routes +
// authz policy) in-process to exercise the actual HTTP handlers for the
// session-write endpoints, exactly as they run in production.
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

		// Mirror main.go's filter chain. The authorization decision this
		// finding is about is enforced in routers.ApiFilter -- without
		// registering the same filter chain main.go wires up, the test
		// server would accept every authenticated request regardless of
		// admin status, masking the very check under test.
		web.InsertFilter("*", web.BeforeStatic, routers.RequestBodyFilter)
		web.InsertFilter("*", web.BeforeStatic, routers.ContentTypeFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.StaticFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.AutoSigninFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.CorsFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.TimeoutFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.ApiFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.PrometheusFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.RecordMessage)
		web.InsertFilter("*", web.BeforeRouter, routers.FieldValidationFilter)
		web.InsertFilter("*", web.AfterExec, routers.AfterRecordMessage, web.WithReturnOnOutput(false))
	})

	return httptest.NewServer(web.BeeApp.Handlers)
}

type sessionApiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func newSessionHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Timeout: 15 * time.Second, Jar: jar}
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

// sessionTestFixture seeds two throwaway organizations. orgA has a standard
// (non-admin) user and an org-admin user; orgB has its own org-admin user,
// used to prove an org admin cannot reach across into another org's
// sessions.
type sessionTestFixture struct {
	OrgA          string
	AppA          string
	AliceName     string
	AlicePass     string
	OrgAdminAName string
	OrgAdminAPass string
	OrgB          string
	AppB          string
	OrgAdminBName string
	OrgAdminBPass string
}

func setupSessionFixture(t *testing.T) sessionTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := "sec-sess-org-a-" + suffix
	appA := "sec-sess-app-a-" + suffix
	orgB := "sec-sess-org-b-" + suffix
	appB := "sec-sess-app-b-" + suffix

	aliceName := "alice"
	alicePass := "NiroTestPass123!"
	orgAdminAName := "org-a-admin"
	orgAdminAPass := "NiroTestPass123!"
	orgAdminBName := "org-b-admin"
	orgAdminBPass := "NiroTestPass123!"

	mkOrg := func(name string) *object.Organization {
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
	mkApp := func(name, org string) *object.Application {
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

	orgAObj := mkOrg(orgA)
	if _, err := object.AddOrganization(orgAObj); err != nil {
		t.Fatalf("failed to create orgA: %v", err)
	}
	appAObj := mkApp(appA, orgA)
	if _, err := object.AddApplication(appAObj); err != nil {
		t.Fatalf("failed to create appA: %v", err)
	}

	orgBObj := mkOrg(orgB)
	if _, err := object.AddOrganization(orgBObj); err != nil {
		t.Fatalf("failed to create orgB: %v", err)
	}
	appBObj := mkApp(appB, orgB)
	if _, err := object.AddApplication(appBObj); err != nil {
		t.Fatalf("failed to create appB: %v", err)
	}

	alice := &object.User{
		Owner:             orgA,
		Name:              aliceName,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          alicePass,
		DisplayName:       "Alice Standard User",
		Email:             "alice-" + suffix + "@example.com",
		IsAdmin:           false,
		SignupApplication: appA,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(alice, "en"); err != nil {
		t.Fatalf("failed to create alice: %v", err)
	}

	orgAdminA := &object.User{
		Owner:             orgA,
		Name:              orgAdminAName,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          orgAdminAPass,
		DisplayName:       "Org A Admin",
		Email:             "org-a-admin-" + suffix + "@example.com",
		IsAdmin:           true,
		SignupApplication: appA,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(orgAdminA, "en"); err != nil {
		t.Fatalf("failed to create org A admin: %v", err)
	}

	orgAdminB := &object.User{
		Owner:             orgB,
		Name:              orgAdminBName,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          orgAdminBPass,
		DisplayName:       "Org B Admin",
		Email:             "org-b-admin-" + suffix + "@example.com",
		IsAdmin:           true,
		SignupApplication: appB,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(orgAdminB, "en"); err != nil {
		t.Fatalf("failed to create org B admin: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteAllUserSessions(orgA, aliceName)
		_, _ = object.DeleteAllUserSessions(orgA, orgAdminAName)
		_, _ = object.DeleteAllUserSessions(orgB, orgAdminBName)
		_, _ = object.DeleteUser(alice)
		_, _ = object.DeleteUser(orgAdminA)
		_, _ = object.DeleteUser(orgAdminB)
		_, _ = object.DeleteApplication(appAObj)
		_, _ = object.DeleteApplication(appBObj)
		_, _ = object.DeleteOrganization(orgAObj)
		_, _ = object.DeleteOrganization(orgBObj)
	})

	return sessionTestFixture{
		OrgA:          orgA,
		AppA:          appA,
		AliceName:     aliceName,
		AlicePass:     alicePass,
		OrgAdminAName: orgAdminAName,
		OrgAdminAPass: orgAdminAPass,
		OrgB:          orgB,
		AppB:          appB,
		OrgAdminBName: orgAdminBName,
		OrgAdminBPass: orgAdminBPass,
	}
}

func sessionLogin(t *testing.T, server *httptest.Server, org, app, username, password string) *http.Client {
	t.Helper()
	client := newSessionHTTPClient()
	resp := sessionDoPostJSON(t, client, server.URL+"/api/login", map[string]interface{}{
		"application":  app,
		"organization": org,
		"username":     username,
		"password":     password,
		"type":         "login",
		"signinMethod": "Password",
	})
	if resp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: could not log in as %s/%s: %s", org, username, resp.Msg)
	}
	return client
}

// TestAddSessionRejectsStandardUserSelfWrite is the regression test for
// TC-EDF8A1C1. It must fail (red) on the unfixed controllers/session.go,
// where AddSession() applies no admin gate and the Casbin matcher's
// self-object clause (subOwner==objOwner && subName==objName) lets a
// standard user write to her own row in the admin-only session table.
func TestAddSessionRejectsStandardUserSelfWrite(t *testing.T) {
	server := bootSessionApp(t)
	defer server.Close()

	fx := setupSessionFixture(t)
	alice := sessionLogin(t, server, fx.OrgA, fx.AppA, fx.AliceName, fx.AlicePass)

	// Positive control: the identical request against a different user
	// (bob, who doesn't even need to exist) must already be rejected. This
	// proves the harness/auth path is healthy and isolates the self-write
	// bypass below.
	crossURL := server.URL + "/api/add-session"
	crossResp := sessionDoPostJSON(t, alice, crossURL, map[string]interface{}{
		"owner":       fx.OrgA,
		"name":        "bob",
		"application": fx.AppA,
		"sessionId":   []string{"forged-cross-user"},
	})
	if crossResp.Status == "ok" {
		t.Fatalf("SETUP FAILURE: cross-user add-session unexpectedly succeeded; environment is broadly broken: %+v", crossResp)
	}

	// Exploit: Alice (non-admin) targets her own owner/name.
	selfResp := sessionDoPostJSON(t, alice, crossURL, map[string]interface{}{
		"owner":       fx.OrgA,
		"name":        fx.AliceName,
		"application": fx.AppA,
		"sessionId":   []string{"forged-self-write"},
	})

	if selfResp.Status == "ok" {
		t.Fatalf("invariant violated: standard user %s/%s wrote to her own row via POST /api/add-session: status=%s msg=%s data=%s",
			fx.OrgA, fx.AliceName, selfResp.Status, selfResp.Msg, string(selfResp.Data))
	}
}

// TestUpdateSessionRejectsStandardUserSelfWrite and
// TestDeleteSessionRejectsStandardUserSelfWrite cover the sibling write
// endpoints, which share the same missing-admin-gate root cause.
func TestUpdateSessionRejectsStandardUserSelfWrite(t *testing.T) {
	server := bootSessionApp(t)
	defer server.Close()

	fx := setupSessionFixture(t)
	alice := sessionLogin(t, server, fx.OrgA, fx.AppA, fx.AliceName, fx.AlicePass)

	resp := sessionDoPostJSON(t, alice, server.URL+"/api/update-session", map[string]interface{}{
		"owner":       fx.OrgA,
		"name":        fx.AliceName,
		"application": fx.AppA,
		"sessionId":   []string{"forged-update"},
	})

	if resp.Status == "ok" {
		t.Fatalf("invariant violated: standard user %s/%s wrote to her own row via POST /api/update-session: status=%s msg=%s data=%s",
			fx.OrgA, fx.AliceName, resp.Status, resp.Msg, string(resp.Data))
	}
}

func TestDeleteSessionRejectsStandardUserSelfWrite(t *testing.T) {
	server := bootSessionApp(t)
	defer server.Close()

	fx := setupSessionFixture(t)

	// Seed a real session row for Alice as global admin so the delete
	// attempt below has a row to (illegitimately) wipe.
	adminClient := sessionLogin(t, server, "built-in", "app-built-in", "admin", "123")
	seedResp := sessionDoPostJSON(t, adminClient, server.URL+"/api/add-session", map[string]interface{}{
		"owner":       fx.OrgA,
		"name":        fx.AliceName,
		"application": fx.AppA,
		"sessionId":   []string{"real-session-1"},
	})
	if seedResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: global admin could not seed Alice's session row: %s", seedResp.Msg)
	}

	alice := sessionLogin(t, server, fx.OrgA, fx.AppA, fx.AliceName, fx.AlicePass)
	resp := sessionDoPostJSON(t, alice, server.URL+"/api/delete-session", map[string]interface{}{
		"owner":       fx.OrgA,
		"name":        fx.AliceName,
		"application": fx.AppA,
	})

	if resp.Status == "ok" {
		t.Fatalf("invariant violated: standard user %s/%s wiped her own row via POST /api/delete-session: status=%s msg=%s data=%s",
			fx.OrgA, fx.AliceName, resp.Status, resp.Msg, string(resp.Data))
	}

	// The real session row must survive the rejected delete.
	pkID := fx.OrgA + "/" + fx.AliceName + "/" + fx.AppA
	after := sessionDoGet(t, adminClient, server.URL+"/api/get-session?sessionPkId="+pkID)
	if after.Status != "ok" || string(after.Data) == "null" {
		t.Fatalf("regression: Alice's real session row was lost even though the delete should have been rejected: status=%s data=%s", after.Status, string(after.Data))
	}
}

// TestAddSessionAllowsOwnOrgAdmin proves the fix does not break the
// legitimate use case: an org admin managing sessions within her own
// organization must still be able to add a session entry.
func TestAddSessionAllowsOwnOrgAdmin(t *testing.T) {
	server := bootSessionApp(t)
	defer server.Close()

	fx := setupSessionFixture(t)
	orgAdminA := sessionLogin(t, server, fx.OrgA, fx.AppA, fx.OrgAdminAName, fx.OrgAdminAPass)

	resp := sessionDoPostJSON(t, orgAdminA, server.URL+"/api/add-session", map[string]interface{}{
		"owner":       fx.OrgA,
		"name":        fx.AliceName,
		"application": fx.AppA,
		"sessionId":   []string{"legit-admin-add"},
	})

	if resp.Status != "ok" {
		t.Fatalf("behavior regression: org A's own admin could not add a session within her own organization: status=%s msg=%s", resp.Status, resp.Msg)
	}
}

// TestAddSessionRejectsCrossOrgAdmin proves an org admin cannot reach across
// into a different organization's session table.
func TestAddSessionRejectsCrossOrgAdmin(t *testing.T) {
	server := bootSessionApp(t)
	defer server.Close()

	fx := setupSessionFixture(t)
	orgAdminB := sessionLogin(t, server, fx.OrgB, fx.AppB, fx.OrgAdminBName, fx.OrgAdminBPass)

	resp := sessionDoPostJSON(t, orgAdminB, server.URL+"/api/add-session", map[string]interface{}{
		"owner":       fx.OrgA,
		"name":        fx.AliceName,
		"application": fx.AppA,
		"sessionId":   []string{"cross-org-admin-write"},
	})

	if resp.Status == "ok" {
		t.Fatalf("invariant violated: org B's admin wrote into org A's session table via POST /api/add-session: status=%s msg=%s data=%s", resp.Status, resp.Msg, string(resp.Data))
	}
}

// TestAddSessionAllowsGlobalAdmin proves the fix does not break the global
// admin's ability to manage sessions across any organization.
func TestAddSessionAllowsGlobalAdmin(t *testing.T) {
	server := bootSessionApp(t)
	defer server.Close()

	fx := setupSessionFixture(t)
	adminClient := sessionLogin(t, server, "built-in", "app-built-in", "admin", "123")

	resp := sessionDoPostJSON(t, adminClient, server.URL+"/api/add-session", map[string]interface{}{
		"owner":       fx.OrgA,
		"name":        fx.AliceName,
		"application": fx.AppA,
		"sessionId":   []string{"legit-global-admin-add"},
	})

	if resp.Status != "ok" {
		t.Fatalf("behavior regression: global admin could no longer add a session for an organization's user: status=%s msg=%s", resp.Status, resp.Msg)
	}
}
