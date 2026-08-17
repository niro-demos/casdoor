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

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// introspectApiTestSetup boots just enough of the app (config + DB connection
// + an in-memory session manager) for ApiController methods to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used elsewhere for controller-level regression tests.
var introspectApiTestSetup sync.Once

func initIntrospectApiTest(t *testing.T) {
	t.Helper()

	introspectApiTestSetup.Do(func() {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			panic("failed to resolve test file path")
		}
		repoRoot := filepath.Dir(filepath.Dir(thisFile))

		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id_test"
		web.BConfig.WebConfig.Session.SessionGCMaxLifetime = 3600

		// Loads conf/app.conf (real MySQL DSN) and registers beego's session
		// manager, mirroring what main.go does at startup.
		web.TestBeegoInit(repoRoot)

		object.InitAdapter()
		object.CreateTables()
		object.InitDb()
		object.InitUserManager()
	})
}

// setupIntrospectOrgAndApp creates an organization plus one application for
// it, with the "password" grant type enabled (required to obtain an access
// token via the resource-owner password grant below) and registers cleanup.
// The application's Cert is intentionally left empty so it falls back to the
// shared built-in cert -- the same configuration app-niro-alpha/app-niro-beta
// have in the live target, and the condition that lets a token verify
// successfully across unrelated applications.
func setupIntrospectOrgAndApp(t *testing.T, orgName string) *object.Application {
	t.Helper()

	org := &object.Organization{
		Owner:        "admin",
		Name:         orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  orgName,
		PasswordType: "plain",
	}
	ok, err := object.AddOrganization(org)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture organization %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(org) })

	app := &object.Application{
		Owner:                "admin",
		Name:                 "app-" + orgName,
		CreatedTime:          util.GetCurrentTime(),
		DisplayName:          "app-" + orgName,
		Organization:         orgName,
		GrantTypes:           []string{"password"},
		ExpireInHours:        24,
		RefreshExpireInHours: 168,
	}
	ok, err = object.AddApplication(app)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture application for %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	return app
}

// setupIntrospectUser creates a user with a plaintext password (matching the
// fixture organization's PasswordType: "plain") and registers cleanup.
func setupIntrospectUser(t *testing.T, orgName, name, password string) *object.User {
	t.Helper()

	user := &object.User{
		Owner:       orgName,
		Name:        name,
		Id:          orgName + "/" + name,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: name,
		Password:    password,
	}
	ok, err := object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s/%s: ok=%v err=%v", orgName, name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// callOAuthToken drives ApiController.GetOAuthToken directly, simulating
// POST /api/login/oauth/access_token with a form-encoded body.
func callOAuthToken(t *testing.T, form url.Values) map[string]interface{} {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(w, req)

	sess, err := web.GlobalSessions.SessionStart(w, req)
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	defer sess.SessionRelease(context.Background(), w)
	ctx.Input.CruSession = sess

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetOAuthToken", nil)
	c.GetOAuthToken()

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode oauth token response body %q: %v", w.Body.String(), err)
	}
	return result
}

// callIntrospectToken drives ApiController.IntrospectToken directly,
// simulating POST /api/login/oauth/introspect with a form-encoded body -- the
// same seam the vulnerability lives in.
func callIntrospectToken(t *testing.T, form url.Values) object.IntrospectionResponse {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/login/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(w, req)

	sess, err := web.GlobalSessions.SessionStart(w, req)
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	defer sess.SessionRelease(context.Background(), w)
	ctx.Input.CruSession = sess

	c := &ApiController{}
	c.Init(ctx, "ApiController", "IntrospectToken", nil)
	c.IntrospectToken()

	var result object.IntrospectionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode introspect response body %q: %v", w.Body.String(), err)
	}
	return result
}

// TestIntrospectTokenRejectsCrossTenantApplication is the regression test for
// TC-ACE9962C: an OAuth client from one tenant application must not be able
// to introspect another tenant's application's token using only its own
// client credentials. The invariant under test (RFC 7662 SS2.2): an
// introspection response must be scoped to the token's own authorized party
// -- a caller that is not the token's owning application must get
// active:false, never the token's real metadata (username, sub, jti, scope).
func TestIntrospectTokenRejectsCrossTenantApplication(t *testing.T) {
	initIntrospectApiTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgAlpha := "introspect-it-alpha-" + suffix
	orgBeta := "introspect-it-beta-" + suffix

	appAlpha := setupIntrospectOrgAndApp(t, orgAlpha)
	appBeta := setupIntrospectOrgAndApp(t, orgBeta)

	victimPassword := "NiroPocPass123!"
	setupIntrospectUser(t, orgAlpha, "alice", victimPassword)

	tokenResp := callOAuthToken(t, url.Values{
		"grant_type":    {"password"},
		"username":      {"alice"},
		"password":      {victimPassword},
		"client_id":     {appAlpha.ClientId},
		"client_secret": {appAlpha.ClientSecret},
	})

	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("failed to obtain access token for alice via her own tenant's application: %+v", tokenResp)
	}

	// Positive control: the token's own owning application (app-alpha)
	// introspects its own token -- must be active, proving the token and the
	// test environment are healthy before the cross-tenant case is judged.
	t.Run("control_owning_application_introspection_allowed", func(t *testing.T) {
		resp := callIntrospectToken(t, url.Values{
			"token":           {accessToken},
			"token_type_hint": {"access_token"},
			"client_id":       {appAlpha.ClientId},
			"client_secret":   {appAlpha.ClientSecret},
		})
		if !resp.Active || resp.Username != "alice" {
			t.Fatalf("control failed: owning application (app-alpha) could not introspect its own token: %+v", resp)
		}
	})

	// Red/green case: an unrelated application in an unrelated tenant
	// (app-beta) has no relationship to app-alpha or alice, yet authenticates
	// with only its own valid client_id/client_secret. It must not be able to
	// introspect app-alpha's token.
	t.Run("cross_tenant_application_introspection_denied", func(t *testing.T) {
		resp := callIntrospectToken(t, url.Values{
			"token":           {accessToken},
			"token_type_hint": {"access_token"},
			"client_id":       {appBeta.ClientId},
			"client_secret":   {appBeta.ClientSecret},
		})
		if resp.Active {
			t.Fatalf("cross-tenant application (app-beta) introspected app-alpha's token and received active:true plus metadata (username=%q sub=%q jti=%q client_id=%q)",
				resp.Username, resp.Sub, resp.Jti, resp.ClientId)
		}
	})
}
