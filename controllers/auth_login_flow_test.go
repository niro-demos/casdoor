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

// Package controllers_test is an external test package (rather than
// `package controllers`) specifically so it can import routers.InitAPI() to
// stand up the real HTTP router: routers already imports controllers to
// register its routes, so importing routers from an internal controllers
// test would be an import cycle.
package controllers_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
	"github.com/casdoor/casdoor/util"
	"github.com/pquerna/otp/totp"
)

// authFlowTestServer is a real, in-process Casdoor HTTP server: the actual
// beego router (registered by routers.InitAPI(), the same call main.go
// makes) wrapped by httptest.NewServer, backed by an isolated sqlite
// database, with beego's session middleware wired up exactly like main.go
// wires it (SessionOn, cookie name "casdoor_session_id", file-backed
// provider). This exercises the real HTTP request/response cycle -
// including Set-Cookie / session-cookie behavior - which is central to two
// of the three invariants under test here (MFA lockout persistence across
// requests, and session-id rotation on login), so a lower-level in-process
// controller call (bypassing HTTP + sessions) would not actually prove
// either one.
var authFlowTestServer *httptest.Server

func TestMain(m *testing.M) {
	os.Exit(runAuthFlowTests(m))
}

func runAuthFlowTests(m *testing.M) int {
	dbFile := filepath.Join(os.TempDir(), fmt.Sprintf("casdoor-auth-flow-test-%d.db", time.Now().UnixNano()))
	defer os.Remove(dbFile)

	// object.InitAdapter()/CreateTables() read driverName/dataSourceName/
	// dbName via conf.GetConfigString, which checks the process environment
	// before conf/app.conf - so this fully overrides the tracked app.conf's
	// mysql defaults with an isolated, throwaway sqlite file, mirroring how
	// niro/harness/start.sh boots Casdoor against sqlite for local runs.
	os.Setenv("driverName", "sqlite")
	os.Setenv("dataSourceName", "file:"+dbFile+"?cache=shared")
	os.Setenv("dbName", "casdoor")

	sessionDir, err := os.MkdirTemp("", "casdoor-auth-flow-sessions-")
	if err != nil {
		fmt.Println("failed to create session temp dir:", err)
		return 2
	}
	defer os.RemoveAll(sessionDir)

	// Same session wiring main.go performs before routers.InitAPI() /
	// web.Run() - required for the casdoor_session_id cookie (and MFA's
	// server-side session state) to work at all.
	web.BConfig.WebConfig.Session.SessionOn = true
	web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"
	web.BConfig.WebConfig.Session.SessionProvider = "file"
	web.BConfig.WebConfig.Session.SessionProviderConfig = sessionDir
	web.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24
	web.BConfig.WebConfig.Session.SessionGCMaxLifetime = 3600 * 24

	routers.InitAPI()

	// object.InitFlag() parses -createDatabase/-config flags (createDatabase
	// defaults to false, which CreateTables() below needs for sqlite - it
	// rejects the mysql-only "CREATE DATABASE IF NOT EXISTS" statement) and
	// loads conf/app.conf; swap os.Args around the call so go test's own
	// flags (-test.run, etc.) don't reach flag.Parse().
	oldArgs := os.Args
	os.Args = []string{oldArgs[0], "-config=../conf/app.conf"}
	object.InitFlag()
	os.Args = oldArgs

	object.InitAdapter()
	object.CreateTables()
	object.InitDb()

	// Registers beego's session/error/mime hooks (in particular
	// registerSession(), which builds web.GlobalSessions from the Session
	// config set above) without starting a real network listener.
	web.InitBeegoBeforeTest("../conf/app.conf")

	authFlowTestServer = httptest.NewServer(web.BeeApp.Handlers)
	defer authFlowTestServer.Close()

	return m.Run()
}

type flowResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func newFlowClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func flowPostJSON(t *testing.T, client *http.Client, path string, body map[string]interface{}) (*http.Response, flowResp) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, authFlowTestServer.URL+path, strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to %s failed: %v", path, err)
	}
	defer resp.Body.Close()
	var fr flowResp
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		t.Fatalf("failed to decode response from %s: %v", path, err)
	}
	return resp, fr
}

func flowGet(t *testing.T, client *http.Client, path string) (*http.Response, flowResp) {
	t.Helper()
	resp, err := client.Get(authFlowTestServer.URL + path)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer resp.Body.Close()
	var fr flowResp
	_ = json.NewDecoder(resp.Body).Decode(&fr)
	return resp, fr
}

// newTestOrgAndApp provisions a fresh, isolated organization + application
// (plain-text passwords, for test simplicity) so each test's fixtures never
// collide and never depend on any externally-seeded org (e.g. the niro
// harness's "acme"). redirectUris, when non-empty, becomes the
// application's registered CAS/OAuth redirect URI allowlist.
func newTestOrgAndApp(t *testing.T, suffix string, redirectUris []string) (*object.Organization, *object.Application) {
	t.Helper()

	orgName := "test-org-" + suffix
	org := &object.Organization{
		Owner:           "admin",
		Name:            orgName,
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     orgName,
		WebsiteUrl:      "https://example.com",
		PasswordType:    "plain",
		PasswordOptions: []string{"AtLeast6"},
		CountryCodes:    []string{"US"},
		Tags:            []string{},
		Languages:       []string{"en"},
		InitScore:       0,
		AccountItems:    object.GetDefaultAccountItems(),
	}
	ok, err := object.AddOrganization(org)
	if err != nil {
		t.Fatalf("failed to create test organization: %v", err)
	}
	if !ok {
		t.Fatalf("creating test organization had no effect")
	}

	appName := "test-app-" + suffix
	app := &object.Application{
		Owner:          "admin",
		Name:           appName,
		CreatedTime:    util.GetCurrentTime(),
		DisplayName:    appName,
		Organization:   orgName,
		EnablePassword: true,
		EnableSignUp:   true,
		RedirectUris:   redirectUris,
	}
	ok, err = object.AddApplication(app)
	if err != nil {
		t.Fatalf("failed to create test application: %v", err)
	}
	if !ok {
		t.Fatalf("creating test application had no effect")
	}

	return org, app
}

// newTestUser provisions a throwaway user in org's own organization with a
// known plaintext password.
func newTestUser(t *testing.T, org *object.Organization, name, password string) *object.User {
	t.Helper()

	user := &object.User{
		Owner:       org.Name,
		Name:        name,
		CreatedTime: util.GetCurrentTime(),
		Type:        "normal-user",
		Password:    password,
		DisplayName: name,
		Email:       name + "@example.com",
	}
	ok, err := object.AddUser(user, "en")
	if err != nil {
		t.Fatalf("failed to create test user %s: %v", name, err)
	}
	if !ok {
		t.Fatalf("creating test user %s had no effect", name)
	}

	created, err := object.GetUser(user.GetId())
	if err != nil || created == nil {
		t.Fatalf("failed to read back created test user %s: %v", name, err)
	}
	return created
}

// ---------------------------------------------------------------------
// TC-372760A6: CAS ticket-validation pgtUrl SSRF via missing service
// validation in Login()'s CAS branch.
//
// Invariant: an authenticated user must not be able to mint a CAS service
// ticket for a `service` value that is not in the application's registered
// RedirectUris - the same allowlist GetApplicationLogin() already enforces
// via object.CheckCasLogin() for the cas type.
// ---------------------------------------------------------------------
func TestCasLoginRejectsUnregisteredService(t *testing.T) {
	registeredService := "https://allowed.example.test/callback"
	unregisteredService := "https://attacker-controlled.example.test/callback"

	org, app := newTestOrgAndApp(t, "cas372760a6", []string{registeredService})
	password := "Test-Pw1!"
	user := newTestUser(t, org, "cas-user", password)

	t.Run("registered service is accepted (control)", func(t *testing.T) {
		client := newFlowClient(t)
		path := "/api/login?service=" + url.QueryEscape(registeredService)
		_, resp := flowPostJSON(t, client, path, map[string]interface{}{
			"username":     user.Name,
			"password":     password,
			"organization": org.Name,
			"application":  app.Name,
			"type":         "cas",
		})

		var ticket string
		_ = json.Unmarshal(resp.Data, &ticket)
		if resp.Status != "ok" || !strings.HasPrefix(ticket, "ST-") {
			t.Fatalf("control failed: a registered service must be accepted and minted a service ticket; got status=%q data=%s", resp.Status, resp.Data)
		}
	})

	t.Run("unregistered service is rejected (red case / TC-372760A6)", func(t *testing.T) {
		client := newFlowClient(t)
		path := "/api/login?service=" + url.QueryEscape(unregisteredService)
		_, resp := flowPostJSON(t, client, path, map[string]interface{}{
			"username":     user.Name,
			"password":     password,
			"organization": org.Name,
			"application":  app.Name,
			"type":         "cas",
		})

		var ticket string
		_ = json.Unmarshal(resp.Data, &ticket)
		if resp.Status == "ok" && strings.HasPrefix(ticket, "ST-") {
			t.Fatalf("VULNERABLE: minted a CAS service ticket (%s) for service %q, which is not in application %q's registered RedirectUris (%v). "+
				"This ticket can later be redeemed at the public serviceValidate endpoint with an attacker-chosen pgtUrl, making the server dial out "+
				"to an arbitrary attacker-controlled host (SSRF).", ticket, unregisteredService, app.Name, app.RedirectUris)
		}
		if resp.Status != "error" {
			t.Fatalf("expected an error response for an unregistered service, got status=%q data=%s", resp.Status, resp.Data)
		}
	})
}

// TestCasProxyValidateRejectsUnregisteredPgtUrl covers the second half of
// TC-372760A6: even once ticket-minting is pinned to a registered service
// (TestCasLoginRejectsUnregisteredService above), the public
// p3/proxyValidate endpoint must still refuse to dial an arbitrary
// caller-supplied pgtUrl when redeeming an otherwise-legitimate ticket -
// otherwise any authenticated user can request a ticket for the
// application's own registered (and therefore allowed) service, then
// redeem it with an unrelated attacker-chosen pgtUrl and get the same SSRF.
func TestCasProxyValidateRejectsUnregisteredPgtUrl(t *testing.T) {
	registeredService := "https://allowed.example.test/callback"
	org, app := newTestOrgAndApp(t, "casssrf372760a6", []string{registeredService})
	password := "Test-Pw1!"
	user := newTestUser(t, org, "cas-ssrf-user", password)

	mintTicket := func(t *testing.T) string {
		t.Helper()
		client := newFlowClient(t)
		path := "/api/login?service=" + url.QueryEscape(registeredService)
		_, resp := flowPostJSON(t, client, path, map[string]interface{}{
			"username":     user.Name,
			"password":     password,
			"organization": org.Name,
			"application":  app.Name,
			"type":         "cas",
		})
		var ticket string
		_ = json.Unmarshal(resp.Data, &ticket)
		if resp.Status != "ok" || !strings.HasPrefix(ticket, "ST-") {
			t.Fatalf("setup failed: could not mint a ticket for the registered service: status=%q data=%s", resp.Status, resp.Data)
		}
		return ticket
	}

	t.Run("registered pgtUrl passes the allowlist (control)", func(t *testing.T) {
		ticket := mintTicket(t)
		validateURL := fmt.Sprintf("%s/cas/%s/%s/p3/proxyValidate?service=%s&ticket=%s&pgtUrl=%s&format=json",
			authFlowTestServer.URL, org.Name, app.Name,
			url.QueryEscape(registeredService), url.QueryEscape(ticket), url.QueryEscape(registeredService))
		httpResp, err := http.Get(validateURL)
		if err != nil {
			t.Fatalf("GET %s failed: %v", validateURL, err)
		}
		defer httpResp.Body.Close()
		var body map[string]interface{}
		_ = json.NewDecoder(httpResp.Body).Decode(&body)
		if failure, ok := body["Failure"].(map[string]interface{}); ok {
			if msg, _ := failure["Message"].(string); strings.Contains(msg, "allowed Redirect URI list") {
				t.Fatalf("control failed: pgtUrl %q is one of application %q's own registered RedirectUris and must pass the allowlist check; got: %v", registeredService, app.Name, failure)
			}
		}
	})

	t.Run("unregistered pgtUrl is rejected and never dialed (red case / TC-372760A6)", func(t *testing.T) {
		// Own, throwaway TCP listener standing in for an internal service the
		// attacker is probing for - if the server actually dials out to it,
		// the connection is observed here: concrete, first-hand proof of the
		// SSRF, not just a parsed error message.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to start local listener: %v", err)
		}
		defer ln.Close()
		port := ln.Addr().(*net.TCPAddr).Port
		attackerPgtUrl := fmt.Sprintf("https://127.0.0.1:%d/x", port)

		connCh := make(chan struct{}, 1)
		go func() {
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			connCh <- struct{}{}
		}()

		ticket := mintTicket(t)
		validateURL := fmt.Sprintf("%s/cas/%s/%s/p3/proxyValidate?service=%s&ticket=%s&pgtUrl=%s&format=json",
			authFlowTestServer.URL, org.Name, app.Name,
			url.QueryEscape(registeredService), url.QueryEscape(ticket), url.QueryEscape(attackerPgtUrl))
		httpResp, err := http.Get(validateURL)
		if err != nil {
			t.Fatalf("GET %s failed: %v", validateURL, err)
		}
		defer httpResp.Body.Close()
		var body map[string]interface{}
		_ = json.NewDecoder(httpResp.Body).Decode(&body)

		select {
		case <-connCh:
			t.Fatalf("VULNERABLE: the server dialed out to the attacker-chosen pgtUrl (127.0.0.1:%d) while redeeming a ticket whose service (%q) is legitimately registered - "+
				"pgtUrl itself was never checked against application %q's RedirectUris (%v). Response: %v", port, registeredService, app.Name, app.RedirectUris, body)
		case <-time.After(1 * time.Second):
			// no outbound connection observed - expected once pgtUrl is
			// validated before the server dials out.
		}

		failure, ok := body["Failure"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected a CAS Failure response for an unregistered pgtUrl, got: %v", body)
		}
		if msg, _ := failure["Message"].(string); !strings.Contains(msg, "allowed Redirect URI list") {
			t.Fatalf("expected the failure to be attributed to pgtUrl not being in the allowed Redirect URI list, got: %v", failure)
		}
	})
}

// ---------------------------------------------------------------------
// TC-E6206B34: MFA (TOTP) step at /api/login has no failed-attempt
// lockout, unlike the password step.
//
// Invariant: the system must limit or lock out repeated incorrect one-time
// passcode submissions during the MFA login step, the same way it already
// limits repeated incorrect password submissions.
// ---------------------------------------------------------------------
func TestMfaPasscodeLockout(t *testing.T) {
	org, app := newTestOrgAndApp(t, "mfae6206b34", nil)
	password := "Test-Pw1!"
	user := newTestUser(t, org, "mfa-user", password)

	// Enroll TOTP MFA directly via the object layer (equivalent to a
	// completed initiate/verify/enable admin flow), so the test owns the
	// secret without needing multiple setup HTTP round-trips.
	secret, err := totp.Generate(totp.GenerateOpts{Issuer: "Casdoor", AccountName: user.GetId()})
	if err != nil {
		t.Fatalf("failed to generate TOTP secret: %v", err)
	}
	user.TotpSecret = secret.Secret()
	user.PreferredMfaType = object.TotpType
	if _, err := object.UpdateUser(user.GetId(), user, []string{"totp_secret", "preferred_mfa_type"}, false); err != nil {
		t.Fatalf("failed to enroll TOTP MFA on test user: %v", err)
	}

	client := newFlowClient(t)

	// First factor: password login reaches the MFA step.
	_, first := flowPostJSON(t, client, "/api/login", map[string]interface{}{
		"username":     user.Name,
		"password":     password,
		"organization": org.Name,
		"application":  app.Name,
		"type":         "login",
	})
	var firstData string
	_ = json.Unmarshal(first.Data, &firstData)
	if first.Status != "ok" || firstData != object.NextMfa {
		t.Fatalf("setup failed: expected first factor to reach the MFA step (status=ok, data=%q), got status=%q data=%s", object.NextMfa, first.Status, first.Data)
	}

	// Second factor: hammer the passcode step with wrong codes. Per
	// GetFailedSigninConfigByUser, the default limit is
	// object.DefaultFailedSigninLimit (5) - fire one more than that so the
	// lockout message must have appeared by the last attempt.
	var lastMsg string
	var sawLockout bool
	attempts := object.DefaultFailedSigninLimit + 1
	for i := 0; i < attempts; i++ {
		_, resp := flowPostJSON(t, client, "/api/login", map[string]interface{}{
			"passcode":     "000000",
			"mfaType":      object.TotpType,
			"organization": org.Name,
			"application":  app.Name,
			"type":         "login",
		})
		lastMsg = resp.Msg
		if strings.Contains(resp.Msg, "too many times") || strings.Contains(resp.Msg, "wait for") {
			sawLockout = true
			break
		}
	}

	if !sawLockout {
		t.Fatalf("VULNERABLE: fired %d wrong TOTP codes against the MFA step with no lockout ever engaging (last response msg: %q). "+
			"The password step freezes the account after object.DefaultFailedSigninLimit (%d) wrong attempts; the MFA step must do the same.",
			attempts, lastMsg, object.DefaultFailedSigninLimit)
	}

	// Even the correct code must now be rejected while frozen.
	correctCode, err := totp.GenerateCode(user.TotpSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("failed to compute correct TOTP code: %v", err)
	}
	_, after := flowPostJSON(t, client, "/api/login", map[string]interface{}{
		"passcode":     correctCode,
		"mfaType":      object.TotpType,
		"organization": org.Name,
		"application":  app.Name,
		"type":         "login",
	})
	var afterData string
	_ = json.Unmarshal(after.Data, &afterData)
	if after.Status == "ok" && afterData == user.GetId() {
		t.Fatalf("VULNERABLE: the correct TOTP code was still accepted immediately after the lockout message, i.e. the account was never actually frozen (response: status=%q data=%s)", after.Status, after.Data)
	}
}

// ---------------------------------------------------------------------
// TC-CCD406F6: session ID is not rotated on login (session fixation).
//
// Invariant: the system must issue a fresh session identifier when a user
// authenticates, instead of continuing to use whatever session ID cookie
// the browser presented before login.
// ---------------------------------------------------------------------
func TestSessionIdRotatesOnLogin(t *testing.T) {
	org, app := newTestOrgAndApp(t, "sessionccd406f6", nil)
	password := "Test-Pw1!"
	user := newTestUser(t, org, "session-user", password)

	victimClient := newFlowClient(t)

	// Step 1: attacker captures a pre-auth session id from an
	// unauthenticated endpoint, then (out of band, not modeled here) plants
	// it in the victim's browser. We simulate that by having the "victim"
	// carry on with this same cookie jar.
	flowGet(t, victimClient, "/api/get-captcha-status?applicationId=admin/"+app.Name)
	serverURL, _ := url.Parse(authFlowTestServer.URL)
	preAuthSID := ""
	for _, c := range victimClient.Jar.Cookies(serverURL) {
		if c.Name == "casdoor_session_id" {
			preAuthSID = c.Value
		}
	}
	if preAuthSID == "" {
		t.Fatalf("harness gap: server did not hand out a casdoor_session_id cookie on an unauthenticated request")
	}

	// Step 2: victim logs in while carrying that same pre-auth cookie.
	_, loginResp := flowPostJSON(t, victimClient, "/api/login", map[string]interface{}{
		"username":     user.Name,
		"password":     password,
		"organization": org.Name,
		"application":  app.Name,
		"type":         "login",
	})
	if loginResp.Status != "ok" {
		t.Fatalf("setup failed: victim login did not succeed: status=%q msg=%q", loginResp.Status, loginResp.Msg)
	}

	// Step 3: attacker, who only ever knew the pre-auth id and never
	// authenticated, tries to use it after the victim's login completed.
	attackerJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("failed to create attacker cookie jar: %v", err)
	}
	attackerJar.SetCookies(serverURL, []*http.Cookie{{Name: "casdoor_session_id", Value: preAuthSID}})
	attackerClient := &http.Client{Jar: attackerJar, Timeout: 10 * time.Second}
	_, attackerResp := flowGet(t, attackerClient, "/api/get-account")

	// Positive control: a second, wholly unrelated pre-auth session id that
	// never touched the victim's login at all must also be denied - proves
	// the harness/environment is healthy and the assertion above is
	// specifically about fixation, not a broken baseline (e.g. get-account
	// always returning ok).
	controlClient := newFlowClient(t)
	flowGet(t, controlClient, "/api/get-captcha-status?applicationId=admin/"+app.Name)
	unrelatedSID := ""
	for _, c := range controlClient.Jar.Cookies(serverURL) {
		if c.Name == "casdoor_session_id" {
			unrelatedSID = c.Value
		}
	}
	if unrelatedSID == "" || unrelatedSID == preAuthSID {
		t.Fatalf("harness gap: could not obtain a second, distinct pre-auth session id for the positive control")
	}
	_, controlResp := flowGet(t, controlClient, "/api/get-account")
	if controlResp.Status == "ok" {
		t.Fatalf("positive control broken: an unrelated, never-authenticated session id was accepted by /api/get-account (%s) - environment is not healthy enough to trust this result", controlResp.Msg)
	}

	if attackerResp.Status == "ok" {
		t.Fatalf("VULNERABLE (session fixation): the attacker's pre-auth session id %q, captured before the victim logged in and never used to "+
			"authenticate, was accepted by /api/get-account AFTER the victim's login completed, returning the victim's own account: %s",
			preAuthSID, attackerResp.Data)
	}
}
