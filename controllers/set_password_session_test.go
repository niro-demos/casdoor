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

package controllers_test

// Regression test for TC-D64E94E5: "Password change does not invalidate
// existing active sessions".
//
// Invariant under test: changing an account's password must invalidate
// that account's other existing active login sessions -- a session cookie
// issued before the password change must stop authenticating requests
// after the change, not just reject new logins with the old password.
//
// This spins up the real beego routing/session/filter stack used by
// main.go (against a throwaway sqlite database) and drives the same
// login -> get-account -> set-password -> get-account sequence as the
// finding's proof-of-concept (niro/findings/TC-D64E94E5/poc.go), but
// against a dedicated test fixture instead of the shared seeded data.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

var (
	testAppInitOnce sync.Once
	testAppServer   *httptest.Server
)

// setUpTestApp bootstraps the Casdoor backend (DB + routes + session +
// filters) once for the controllers test package, backed by a throwaway
// sqlite database, and returns an httptest.Server that serves the real
// beego handler stack -- the same one main.go wires up for production,
// minus the network listeners (ldap/radius) and background jobs that
// don't matter for HTTP-level controller behavior.
func setUpTestApp(t *testing.T) *httptest.Server {
	t.Helper()

	testAppInitOnce.Do(func() {
		dbFile := filepath.Join(t.TempDir(), "casdoor-set-password-test.db")

		// conf.GetConfigString() checks the process environment before
		// falling back to conf/app.conf, so these overrides fully replace
		// the tracked dev config (mysql) without touching it -- the same
		// mechanism niro/harness/start.sh uses to run Casdoor on sqlite.
		envOverrides := map[string]string{
			"driverName":     "sqlite",
			"dataSourceName": fmt.Sprintf("file:%s?cache=shared", dbFile),
			"dbName":         "casdoor",
			"initDataFile":   "", // no init_data.json in this checkout; skip it
			"redisEndpoint":  "",
		}
		for k, v := range envOverrides {
			if err := os.Setenv(k, v); err != nil {
				panic(err)
			}
		}

		// object.InitFlag() is how main.go loads conf/app.conf and decides
		// whether to run `CREATE DATABASE IF NOT EXISTS` (a MySQL-only
		// statement that errors against sqlite); its "-createDatabase" flag
		// defaults to false, which is what we want here. It reads the
		// config path and other flags from os.Args, so swap in a
		// controlled argv for the duration of the call.
		origArgs := os.Args
		os.Args = []string{origArgs[0], "-config=../conf/app.conf"}
		object.InitFlag()
		os.Args = origArgs

		object.InitAdapter() // opens the sqlite engine
		object.CreateTables()
		object.InitDb()      // seeds the built-in org/user/application/cert
		object.InitUserManager()

		authz.InitApi() // populates authz.Enforcer, required by routers.ApiFilter

		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"

		routers.InitAPI()

		// web.BeeApp.Run() (what main.go calls) both starts the session
		// manager (via the private registerSession hook) and binds a real
		// TCP listener. InitBeegoBeforeTest runs the same "before serving"
		// hooks -- including session registration -- without binding a
		// port, which is exactly what an httptest.Server needs.
		web.InitBeegoBeforeTest("../conf/app.conf")

		web.InsertFilter("*", web.BeforeStatic, routers.RequestBodyFilter)
		web.InsertFilter("*", web.BeforeStatic, routers.ContentTypeFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.StaticFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.AutoSigninFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.CorsFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.TimeoutFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.ApiFilter)
		web.InsertFilter("*", web.BeforeRouter, routers.FieldValidationFilter)

		web.BeeApp.Handlers.Init()

		testAppServer = httptest.NewServer(web.BeeApp.Handlers)
	})

	return testAppServer
}

type apiResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func doJSON(t *testing.T, client *http.Client, base, method, path string, body interface{}) *apiResp {
	t.Helper()

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, path, err)
	}

	var ar apiResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		t.Fatalf("unmarshal %s %s response %q: %v", method, path, raw, err)
	}
	return &ar
}

func doForm(t *testing.T, client *http.Client, base, path string, form url.Values) *apiResp {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader([]byte(form.Encode())))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read POST %s response: %v", path, err)
	}

	var ar apiResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		t.Fatalf("unmarshal POST %s response %q: %v", path, raw, err)
	}
	return &ar
}

// newClient returns an http.Client with its own cookie jar, i.e. its own
// independent browser session.
func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{Jar: jar}
}

// setUpPasswordChangeFixture creates a dedicated organization, application,
// and user for this test (mirroring the finding's acme/app-acme/alice
// fixture) so it doesn't depend on or mutate the built-in seed data.
func setUpPasswordChangeFixture(t *testing.T, oldPassword string) (orgName, appName, userName string) {
	t.Helper()

	suffix := fmt.Sprintf("%d", os.Getpid())
	orgName = "org-setpw-" + suffix
	appName = "app-setpw-" + suffix
	userName = "user-setpw-" + suffix

	org := &object.Organization{
		Owner:           "admin",
		Name:            orgName,
		CreatedTime:     "2026-01-01T00:00:00Z",
		DisplayName:     orgName,
		WebsiteUrl:      "https://example.com",
		PasswordType:    "plain",
		PasswordOptions: []string{"AtLeast6"},
		Tags:            []string{},
		Languages:       []string{"en"},
		InitScore:       0,
		AccountItems:    object.GetDefaultAccountItems(),
	}
	if ok, err := object.AddOrganization(org); err != nil || !ok {
		t.Fatalf("AddOrganization(%s): ok=%v err=%v", orgName, ok, err)
	}

	app := &object.Application{
		Owner:          "admin",
		Name:           appName,
		CreatedTime:    "2026-01-01T00:00:00Z",
		DisplayName:    appName,
		Organization:   orgName,
		Cert:           "cert-built-in",
		EnablePassword: true,
		SigninMethods: []*object.SigninMethod{
			{Name: "Password", DisplayName: "Password", Rule: "All"},
		},
		Tags:                []string{},
		RedirectUris:        []string{},
		TokenFormat:         "JWT",
		TokenFields:         []string{},
		ExpireInHours:       168,
		CookieExpireInHours: 720,
	}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("AddApplication(%s): ok=%v err=%v", appName, ok, err)
	}

	user := &object.User{
		Owner:       orgName,
		Name:        userName,
		CreatedTime: "2026-01-01T00:00:00Z",
		Id:          userName,
		Type:        "normal-user",
		Password:    oldPassword,
		DisplayName: userName,
		Email:       userName + "@example.com",
		SignupApplication: appName,
		Properties:  make(map[string]string),
	}
	if ok, err := object.AddUser(user, "en"); err != nil || !ok {
		t.Fatalf("AddUser(%s): ok=%v err=%v", userName, ok, err)
	}

	return orgName, appName, userName
}

// TestSetPasswordInvalidatesExistingSessions is the regression test for
// TC-D64E94E5. It must fail on the unfixed controllers.ApiController.SetPassword
// (the pre-change session cookie keeps authenticating) and pass once
// SetPassword invalidates the account's active sessions after a successful
// password change.
func TestSetPasswordInvalidatesExistingSessions(t *testing.T) {
	server := setUpTestApp(t)
	base := server.URL

	const oldPassword = "OldPass123"
	const newPassword = "NewPass456"

	orgName, appName, userName := setUpPasswordChangeFixture(t, oldPassword)

	victim := newClient(t)

	// Step 1: log in, capture the session cookie.
	loginResp := doJSON(t, victim, base, http.MethodPost, "/api/login", map[string]string{
		"username":     userName,
		"password":     oldPassword,
		"organization": orgName,
		"application":  appName,
		"type":         "login",
	})
	if loginResp.Status != "ok" {
		t.Fatalf("login did not succeed: %+v", loginResp)
	}

	// Step 2 (positive control): the fresh cookie must be authenticated
	// before any password change -- otherwise a later "red" would be
	// meaningless (broken fixture, not the invariant under test).
	preChange := doJSON(t, victim, base, http.MethodGet, "/api/get-account", nil)
	if preChange.Status != "ok" {
		t.Fatalf("positive control failed: fresh session cookie was not authenticated: %+v", preChange)
	}

	// Step 3: change the password using the SAME session.
	form := url.Values{}
	form.Set("userOwner", orgName)
	form.Set("userName", userName)
	form.Set("oldPassword", oldPassword)
	form.Set("newPassword", newPassword)
	spResp := doForm(t, victim, base, "/api/set-password", form)
	if spResp.Status != "ok" {
		t.Fatalf("set-password did not succeed (cannot test invariant without a real password change): %+v", spResp)
	}

	// Step 4: confirm the change actually took effect server-side.
	oldLoginClient := newClient(t)
	oldLogin := doJSON(t, oldLoginClient, base, http.MethodPost, "/api/login", map[string]string{
		"username":     userName,
		"password":     oldPassword,
		"organization": orgName,
		"application":  appName,
		"type":         "login",
	})
	if oldLogin.Status == "ok" {
		t.Fatalf("password change did not take effect: old password still logs in")
	}

	newLoginClient := newClient(t)
	newLogin := doJSON(t, newLoginClient, base, http.MethodPost, "/api/login", map[string]string{
		"username":     userName,
		"password":     newPassword,
		"organization": orgName,
		"application":  appName,
		"type":         "login",
	})
	if newLogin.Status != "ok" {
		t.Fatalf("password change did not take effect: new password does not log in: %+v", newLogin)
	}

	// Step 5 (the invariant): re-send the exact same request as step 2
	// with the unchanged, pre-change session cookie. A properly-defended
	// system rejects it -- the credential that session was issued under
	// is no longer valid.
	postChange := doJSON(t, victim, base, http.MethodGet, "/api/get-account", nil)
	if postChange.Status == "ok" {
		t.Fatalf("VULNERABLE: pre-password-change session cookie still authenticates after the "+
			"password was changed (and confirmed changed server-side: old password now rejected, "+
			"new password now works). get-account response: status=%q msg=%q data=%s",
			postChange.Status, postChange.Msg, string(postChange.Data))
	}
}
