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

// Regression test for: TOTP app-MFA could be enabled via POST
// /api/mfa/setup/enable without ever proving possession of the secret,
// because MfaSetupEnable trusted the client-supplied "secret" form field
// instead of requiring that it had just been proven with a correct passcode
// via MfaSetupVerify in the same session.
//
// Invariant under test: a user must prove possession of a working
// authenticator (a correct one-time passcode from the secret being
// enrolled) before that secret is activated as a required second factor on
// their account.
//
// This drives the real ApiController.MfaSetupVerify / MfaSetupEnable
// handlers with a real beego session (in-memory provider) carried across
// requests exactly like a browser cookie would, and a real Casdoor
// database connection (per this project's own conf/app.conf and existing
// object-package test conventions), so it exercises the exact code path the
// fix changed rather than a re-implementation of it.
package controllers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/beego/beego/v2/server/web/session"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/pquerna/otp/totp"
)

var mfaTestSetupOnce sync.Once

// initMfaTestDb wires up just the database layer this project's own
// object-package tests already rely on (object.InitConfig loads
// conf/app.conf and connects to the configured database), plus the pieces
// MfaSetupEnable / DeleteUser need (a resolvable organization/application
// and an initialized user-group enforcer). It never starts an HTTP
// listener or touches routing/authz, so it can't collide with any other
// running instance of the app.
func initMfaTestDb(t *testing.T) {
	mfaTestSetupOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
		object.InitUserManager()
	})
}

// mfaTestFixture is a throwaway organization + application + user created
// purely for this test, independent of any seeded/shared fixtures, and
// torn down afterwards.
type mfaTestFixture struct {
	t            *testing.T
	organization *object.Organization
	application  *object.Application
	user         *object.User
}

func newMfaTestFixture(t *testing.T) *mfaTestFixture {
	initMfaTestDb(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "mfa-test-org-" + suffix
	appName := "mfa-test-app-" + suffix
	userName := "mfa-test-user-" + suffix

	organization := &object.Organization{
		Owner:        "admin",
		Name:         orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  orgName,
		PasswordType: "plain",
	}
	ok, err := object.AddOrganization(organization)
	if err != nil || !ok {
		t.Fatalf("failed to create throwaway test organization: ok=%v err=%v", ok, err)
	}

	application := &object.Application{
		Owner:        "admin",
		Name:         appName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  appName,
		Organization: orgName,
	}
	ok, err = object.AddApplication(application)
	if err != nil || !ok {
		t.Fatalf("failed to create throwaway test application: ok=%v err=%v", ok, err)
	}

	user := &object.User{
		Owner:             orgName,
		Name:              userName,
		Id:                util.GenerateId(),
		CreatedTime:       util.GetCurrentTime(),
		Type:              "normal-user",
		DisplayName:       userName,
		Email:             userName + "@example.com",
		SignupApplication: appName,
	}
	ok, err = object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create throwaway test user: ok=%v err=%v", ok, err)
	}

	f := &mfaTestFixture{t: t, organization: organization, application: application, user: user}
	t.Cleanup(f.cleanup)
	return f
}

func (f *mfaTestFixture) cleanup() {
	// Best-effort cleanup regardless of pass/fail, mirroring the PoC's own
	// defer-based teardown.
	_, _ = object.DeleteUser(f.user)
	_, _ = object.DeleteApplication(f.application)
	_, _ = object.DeleteOrganization(f.organization)
}

// mfaTestSession models one continuous authenticated browser session: the
// session cookie returned by the first request is carried into subsequent
// requests, so MfaSetupVerify and MfaSetupEnable observe the same
// server-side session state that the fix binds together (exactly like a
// real browser would across the Verify -> Enable steps).
type mfaTestSession struct {
	t       *testing.T
	manager *session.Manager
	cookie  *http.Cookie
}

func newMfaTestSession(t *testing.T) *mfaTestSession {
	cfg := &session.ManagerConfig{
		CookieName:      "casdoor_mfa_test_session",
		EnableSetCookie: true,
		Gclifetime:      3600,
		Maxlifetime:     3600,
		SessionIDLength: 16,
	}
	manager, err := session.NewManager("memory", cfg)
	if err != nil {
		t.Fatalf("failed to create in-memory session manager: %v", err)
	}
	return &mfaTestSession{t: t, manager: manager}
}

type mfaTestResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

// call invokes the given ApiController action (e.g. (*controllers.ApiController).MfaSetupVerify)
// as a form-encoded POST carrying this session's cookie, exactly as the
// real /api/mfa/setup/* endpoints receive it, and decodes the JSON
// response body.
func (s *mfaTestSession) call(t *testing.T, action func(*controllers.ApiController), path string, form url.Values) *mfaTestResponse {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "http://testserver"+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("failed to parse form: %v", err)
	}
	if s.cookie != nil {
		req.AddCookie(s.cookie)
	}

	rw := httptest.NewRecorder()

	sess, err := s.manager.SessionStart(rw, req)
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	if cookies := rw.Result().Cookies(); len(cookies) > 0 {
		s.cookie = cookies[0]
	}

	ctx := beegoContext.NewContext()
	ctx.Reset(rw, req)
	ctx.Input.CruSession = sess

	c := &controllers.ApiController{}
	c.Init(ctx, "ApiController", "", nil)

	action(c)

	resp := &mfaTestResponse{}
	if err := json.Unmarshal(rw.Body.Bytes(), resp); err != nil {
		t.Fatalf("could not decode JSON response from %s: %v (body=%s)", path, err, rw.Body.String())
	}
	return resp
}

func (s *mfaTestSession) verify(t *testing.T, form url.Values) *mfaTestResponse {
	return s.call(t, func(c *controllers.ApiController) { c.MfaSetupVerify() }, "/api/mfa/setup/verify", form)
}

func (s *mfaTestSession) enable(t *testing.T, form url.Values) *mfaTestResponse {
	return s.call(t, func(c *controllers.ApiController) { c.MfaSetupEnable() }, "/api/mfa/setup/enable", form)
}

// generateTotpSecret returns a fresh, valid base32 TOTP secret the same way
// MfaSetupInitiate does, plus a currently-valid passcode for it.
func generateTotpSecret(t *testing.T) (secret string, passcode string) {
	t.Helper()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "casdoor-test", AccountName: "mfa-test"})
	if err != nil {
		t.Fatalf("failed to generate totp secret: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp passcode: %v", err)
	}
	return key.Secret(), code
}

// TestMfaSetupEnable_RejectsUnverifiedTotpSecret is the red case: it
// reproduces the finding directly against the unfixed code by calling
// /api/mfa/setup/enable with an attacker-chosen secret and NO prior
// successful /api/mfa/setup/verify call for that secret in the session.
func TestMfaSetupEnable_RejectsUnverifiedTotpSecret(t *testing.T) {
	fixture := newMfaTestFixture(t)
	sess := newMfaTestSession(t)

	plantedSecret := "AAAAAAAAAAAAAAAA" // never submitted to MfaSetupVerify

	resp := sess.enable(t, url.Values{
		"owner":         {fixture.organization.Name},
		"name":          {fixture.user.Name},
		"mfaType":       {object.TotpType},
		"secret":        {plantedSecret},
		"recoveryCodes": {"unverified-attempt-recovery-code"},
	})

	if resp.Status != "error" {
		t.Fatalf("REPRODUCED: MfaSetupEnable accepted a TOTP secret that was never verified via "+
			"MfaSetupVerify (status=%q, msg=%q); expected it to be rejected", resp.Status, resp.Msg)
	}

	// Confirm the account-level invariant too: the planted secret must not
	// have been persisted as the user's TOTP secret.
	stored, err := object.GetUser(fixture.user.GetId())
	if err != nil {
		t.Fatalf("failed to reload user: %v", err)
	}
	if stored.TotpSecret == plantedSecret {
		t.Fatalf("REPRODUCED: unverified planted secret %q was persisted as the user's TotpSecret", plantedSecret)
	}
}

// TestMfaSetupEnable_MismatchedVerifiedSecretRejected verifies that
// verifying one secret does not authorize enabling a *different* secret
// (an attacker cannot verify a throwaway passcode for their own secret and
// then swap in another one at the enable step).
func TestMfaSetupEnable_MismatchedVerifiedSecretRejected(t *testing.T) {
	fixture := newMfaTestFixture(t)
	sess := newMfaTestSession(t)

	verifiedSecret, passcode := generateTotpSecret(t)
	swappedSecret := "CCCCCCCCCCCCCCCC"

	verifyResp := sess.verify(t, url.Values{
		"mfaType":  {object.TotpType},
		"secret":   {verifiedSecret},
		"passcode": {passcode},
	})
	if verifyResp.Status != "ok" {
		t.Fatalf("setup: legitimate MfaSetupVerify call failed unexpectedly: status=%q msg=%q", verifyResp.Status, verifyResp.Msg)
	}

	enableResp := sess.enable(t, url.Values{
		"owner":         {fixture.organization.Name},
		"name":          {fixture.user.Name},
		"mfaType":       {object.TotpType},
		"secret":        {swappedSecret},
		"recoveryCodes": {"swapped-secret-recovery-code"},
	})

	if enableResp.Status != "error" {
		t.Fatalf("REPRODUCED: MfaSetupEnable accepted secret %q after only %q was verified "+
			"(status=%q, msg=%q)", swappedSecret, verifiedSecret, enableResp.Status, enableResp.Msg)
	}
}

// TestMfaSetupEnable_AllowsVerifiedTotpSecret is the paired positive
// control: the legitimate Verify-then-Enable flow (same secret, correct
// passcode, same session) must keep working after the fix.
func TestMfaSetupEnable_AllowsVerifiedTotpSecret(t *testing.T) {
	fixture := newMfaTestFixture(t)
	sess := newMfaTestSession(t)

	secret, passcode := generateTotpSecret(t)

	verifyResp := sess.verify(t, url.Values{
		"mfaType":  {object.TotpType},
		"secret":   {secret},
		"passcode": {passcode},
	})
	if verifyResp.Status != "ok" {
		t.Fatalf("legitimate MfaSetupVerify call failed: status=%q msg=%q", verifyResp.Status, verifyResp.Msg)
	}

	enableResp := sess.enable(t, url.Values{
		"owner":         {fixture.organization.Name},
		"name":          {fixture.user.Name},
		"mfaType":       {object.TotpType},
		"secret":        {secret},
		"recoveryCodes": {"legitimate-recovery-code"},
	})
	if enableResp.Status != "ok" {
		t.Fatalf("legitimate MfaSetupEnable call was rejected after a matching successful verify: status=%q msg=%q",
			enableResp.Status, enableResp.Msg)
	}

	stored, err := object.GetUser(fixture.user.GetId())
	if err != nil {
		t.Fatalf("failed to reload user: %v", err)
	}
	if stored.TotpSecret != secret {
		t.Fatalf("expected user's TotpSecret to be set to the verified secret %q, got %q", secret, stored.TotpSecret)
	}

	// Replay: the same verified secret must not be accepted a second time
	// once it has been consumed by a successful enable.
	replayResp := sess.enable(t, url.Values{
		"owner":         {fixture.organization.Name},
		"name":          {fixture.user.Name},
		"mfaType":       {object.TotpType},
		"secret":        {secret},
		"recoveryCodes": {"replay-recovery-code"},
	})
	if replayResp.Status != "error" {
		t.Fatalf("REPRODUCED: a previously-consumed verified secret was accepted again by MfaSetupEnable "+
			"(status=%q, msg=%q)", replayResp.Status, replayResp.Msg)
	}
}
