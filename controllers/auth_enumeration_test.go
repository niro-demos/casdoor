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
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/mock"
	"github.com/casdoor/casdoor/object"
)

type authEnumerationResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

var setupAuthEnumerationOnce sync.Once
var authEnumerationTempDir string

func setupAuthEnumerationTest(t *testing.T) {
	t.Helper()

	setupAuthEnumerationOnce.Do(func() {
		var err error
		authEnumerationTempDir, err = os.MkdirTemp("", "casdoor-auth-enumeration-*")
		if err != nil {
			t.Fatal(err)
		}
		dbPath := filepath.Join(authEnumerationTempDir, "casdoor-auth-enumeration.sqlite")
		t.Setenv("driverName", "sqlite")
		t.Setenv("dataSourceName", "file:"+dbPath+"?cache=shared")
		t.Setenv("dbName", "")
		t.Setenv("origin", "http://example.com")

		initObjectConfigForAuthEnumerationTest()
		web.BConfig.WebConfig.Session.SessionOn = true
		mock.NewSessionProvider("memory")
		object.InitAdapter()
		object.CreateTables()
		object.InitDb()

		web.Router("/api/login", &ApiController{}, "POST:Login")
		web.Router("/api/send-verification-code", &ApiController{}, "POST:SendVerificationCode")
		web.Router("/api/webauthn/signin/begin", &ApiController{}, "GET:WebAuthnSigninBegin")
		web.Router("/api/faceid-signin-begin", &ApiController{}, "GET:FaceIDSigninBegin")
	})
}

func TestPasswordRecoveryDoesNotRevealAccountExistence(t *testing.T) {
	setupAuthEnumerationTest(t)

	existing := postVerificationCode(t, "admin@example.com", "admin")
	missing := postVerificationCode(t, "not-a-user@example.test", "not-a-user-auth-enumeration")

	assertIndistinguishableAuthFailure(t, existing, missing)
}

func TestPasswordSigninDoesNotRevealAccountExistence(t *testing.T) {
	setupAuthEnumerationTest(t)

	existing := postLogin(t, "admin")
	missing := postLogin(t, "not-a-user-auth-enumeration")

	assertIndistinguishableAuthFailure(t, existing, missing)
}

func TestWebAuthnSigninBeginDoesNotRevealAccountExistence(t *testing.T) {
	setupAuthEnumerationTest(t)

	existing := getResponse(t, "/api/webauthn/signin/begin?owner=built-in&name=admin")
	missing := getResponse(t, "/api/webauthn/signin/begin?owner=built-in&name=not-a-user-auth-enumeration")

	assertIndistinguishableAuthFailure(t, existing, missing)
}

func TestFaceIDSigninBeginDoesNotRevealAccountExistence(t *testing.T) {
	setupAuthEnumerationTest(t)

	existing := getResponse(t, "/api/faceid-signin-begin?owner=built-in&name=admin")
	missing := getResponse(t, "/api/faceid-signin-begin?owner=built-in&name=not-a-user-auth-enumeration")

	assertIndistinguishableAuthFailure(t, existing, missing)
}

func postVerificationCode(t *testing.T, dest string, checkUser string) authEnumerationResponse {
	t.Helper()

	form := url.Values{}
	form.Set("type", "email")
	form.Set("dest", dest)
	form.Set("applicationId", "admin/app-built-in")
	form.Set("method", ForgetVerification)
	form.Set("checkUser", checkUser)
	form.Set("captchaType", "none")

	return doRequest(t, http.MethodPost, "/api/send-verification-code", "application/x-www-form-urlencoded", []byte(form.Encode()))
}

func postLogin(t *testing.T, username string) authEnumerationResponse {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"application":  "app-built-in",
		"organization": "built-in",
		"username":     username,
		"password":     "wrong-password-auth-enumeration",
		"signinMethod": "Password",
		"type":         "login",
	})
	if err != nil {
		t.Fatal(err)
	}

	return doRequest(t, http.MethodPost, "/api/login", "application/json", body)
}

func getResponse(t *testing.T, path string) authEnumerationResponse {
	t.Helper()

	return doRequest(t, http.MethodGet, path, "", nil)
}

func doRequest(t *testing.T, method string, path string, contentType string, body []byte) authEnumerationResponse {
	t.Helper()

	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Host = "example.com"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	recorder := httptest.NewRecorder()
	web.BeeApp.Handlers.ServeHTTP(recorder, req)

	data, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s %s returned HTTP %d: %s", method, path, recorder.Code, bytes.TrimSpace(data))
	}

	var response authEnumerationResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("%s %s returned invalid JSON %q: %v", method, path, bytes.TrimSpace(data), err)
	}
	return response
}

func assertIndistinguishableAuthFailure(t *testing.T, existing authEnumerationResponse, missing authEnumerationResponse) {
	t.Helper()

	if existing.Msg != missing.Msg {
		t.Fatalf("public auth response reveals account existence:\nexisting user: %q\nmissing user:  %q", existing.Msg, missing.Msg)
	}
	if existing.Status != missing.Status {
		t.Fatalf("public auth response status differs:\nexisting user: %q\nmissing user:  %q", existing.Status, missing.Status)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if authEnumerationTempDir != "" {
		_ = os.RemoveAll(authEnumerationTempDir)
	}
	os.Exit(code)
}

func initObjectConfigForAuthEnumerationTest() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	oldArgs := os.Args
	os.Args = []string{oldArgs[0], "-createDatabase=false", "-config=../conf/app.conf"}
	defer func() {
		os.Args = oldArgs
	}()

	object.InitFlag()
}
