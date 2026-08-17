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
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/mock"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

const (
	testOrg           = "niro-account-enum"
	testApp           = "app-account-enum"
	testExistingName  = "alice"
	testExistingEmail = "alice@example.test"
	testMissingName   = "does-not-exist"
	testMissingEmail  = "missing@example.test"
)

func setupAccountEnumerationTest(t *testing.T) {
	t.Helper()

	mustSetConfig(t, "driverName", "sqlite")
	mustSetConfig(t, "dataSourceName", filepath.Join(t.TempDir(), "casdoor-test.db"))
	mustSetConfig(t, "dbName", "")
	mustSetConfig(t, "tableNamePrefix", "")
	mustSetConfig(t, "runmode", "dev")
	mustSetConfig(t, "appname", "casdoor-test")
	mustSetConfig(t, "origin", "http://localhost:8000")
	mustSetConfig(t, "originFrontend", "")
	mustSetConfig(t, "defaultLanguage", "en")
	mustSetConfig(t, "forceLanguage", "")
	mustSetConfig(t, "enableErrorMask2", "false")

	web.BConfig.CopyRequestBody = true
	web.BConfig.WebConfig.Session.SessionOn = true
	mock.NewSessionProvider("account-enumeration-test")
	object.SetCreateDatabaseForTesting(false)
	object.InitAdapter()
	object.CreateTables()

	_, err := object.AddOrganization(&object.Organization{
		Owner:                  "admin",
		Name:                   testOrg,
		CreatedTime:            util.GetCurrentTime(),
		DisplayName:            "Niro Account Enumeration",
		PasswordType:           "bcrypt",
		CountryCodes:           []string{"US"},
		AccountItems:           object.GetDefaultAccountItems(),
		MasterVerificationCode: "",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = object.AddApplication(&object.Application{
		Owner:        "admin",
		Name:         testApp,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "Account Enumeration App",
		Organization: testOrg,
		Providers:    []*object.ProviderItem{},
		SigninItems: []*object.SigninItem{
			{Name: "Forgot password?", Visible: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = object.AddUser(&object.User{
		Owner:       testOrg,
		Name:        testExistingName,
		CreatedTime: util.GetCurrentTime(),
		Id:          util.GenerateId(),
		Email:       testExistingEmail,
	}, "en")
	if err != nil {
		t.Fatal(err)
	}
}

func mustSetConfig(t *testing.T, key string, value string) {
	t.Helper()
	if err := web.AppConfig.Set(key, value); err != nil {
		t.Fatal(err)
	}
}

func performRequest(t *testing.T, method string, target string, body io.Reader, contentType string, routes func(*web.ControllerRegister)) Response {
	t.Helper()

	req := httptest.NewRequest(method, target, body)
	req.Host = "localhost:8000"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()

	handler := web.NewControllerRegister()
	routes(handler)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("%s %s returned HTTP %d: %s", method, target, recorder.Code, recorder.Body.String())
	}

	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response %q: %v", recorder.Body.String(), err)
	}
	return response
}

func postVerificationCodeRequest(t *testing.T, dest string) Response {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	fields := map[string]string{
		"captchaType":   "none",
		"method":        LoginVerification,
		"type":          object.VerifyTypeEmail,
		"applicationId": util.GetId("admin", testApp),
		"dest":          dest,
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return performRequest(t, http.MethodPost, "/api/send-verification-code", &body, writer.FormDataContentType(), func(handler *web.ControllerRegister) {
		handler.Add("/api/send-verification-code", &ApiController{}, web.WithRouterMethods(&ApiController{}, "post:SendVerificationCode"))
	})
}

func TestSendVerificationCodeLoginIsAccountAgnostic(t *testing.T) {
	setupAccountEnumerationTest(t)

	existing := postVerificationCodeRequest(t, testExistingEmail)
	missing := postVerificationCodeRequest(t, testMissingEmail)

	assertIndistinguishable(t, "send verification code", existing, missing)
}

func TestVerifyCodeFailureIsAccountAgnostic(t *testing.T) {
	setupAccountEnumerationTest(t)

	request := func(username string) Response {
		body := bytes.NewBufferString(`{"organization":"` + testOrg + `","username":"` + username + `","code":"000000"}`)
		return performRequest(t, http.MethodPost, "/api/verify-code", body, "application/json", func(handler *web.ControllerRegister) {
			handler.Add("/api/verify-code", &ApiController{}, web.WithRouterMethods(&ApiController{}, "post:VerifyCode"))
		})
	}

	existing := request(testExistingEmail)
	missing := request(testMissingEmail)

	assertIndistinguishableError(t, "verify code", existing, missing)
	assertMessageOmits(t, "verify code", missing.Msg, testMissingEmail, util.GetId(testOrg, testMissingEmail))
}

func TestFaceIDSigninBeginIsAccountAgnostic(t *testing.T) {
	setupAccountEnumerationTest(t)

	request := func(name string) Response {
		values := url.Values{}
		values.Set("owner", testOrg)
		values.Set("name", name)
		return performRequest(t, http.MethodGet, "/api/faceid-signin-begin?"+values.Encode(), nil, "", func(handler *web.ControllerRegister) {
			handler.Add("/api/faceid-signin-begin", &ApiController{}, web.WithRouterMethods(&ApiController{}, "get:FaceIDSigninBegin"))
		})
	}

	existing := request(testExistingName)
	missing := request(testMissingName)

	assertIndistinguishable(t, "FaceID sign-in begin", existing, missing)
	assertMessageOmits(t, "FaceID sign-in begin", missing.Msg, testMissingName, util.GetId(testOrg, testMissingName))
}

func TestWebAuthnSigninBeginIsAccountAgnostic(t *testing.T) {
	setupAccountEnumerationTest(t)

	request := func(name string) Response {
		values := url.Values{}
		values.Set("owner", testOrg)
		values.Set("name", name)
		return performRequest(t, http.MethodGet, "/api/webauthn/signin/begin?"+values.Encode(), nil, "", func(handler *web.ControllerRegister) {
			handler.Add("/api/webauthn/signin/begin", &ApiController{}, web.WithRouterMethods(&ApiController{}, "get:WebAuthnSigninBegin"))
		})
	}

	existing := request(testExistingName)
	missing := request(testMissingName)

	assertIndistinguishableError(t, "WebAuthn sign-in begin", existing, missing)
	assertMessageOmits(t, "WebAuthn sign-in begin", missing.Msg, testMissingName, util.GetId(testOrg, testMissingName))
}

func assertIndistinguishableError(t *testing.T, label string, existing Response, missing Response) {
	t.Helper()

	if existing.Status != "error" || missing.Status != "error" {
		t.Fatalf("%s responses must both be ordinary errors, got existing=%q missing=%q", label, existing.Status, missing.Status)
	}
	assertIndistinguishable(t, label, existing, missing)
}

func assertIndistinguishable(t *testing.T, label string, existing Response, missing Response) {
	t.Helper()

	if existing.Status != missing.Status {
		t.Fatalf("%s distinguishes account state: existing status=%q missing status=%q", label, existing.Status, missing.Status)
	}
	if existing.Msg != missing.Msg {
		t.Fatalf("%s distinguishes account state: existing msg=%q missing msg=%q", label, existing.Msg, missing.Msg)
	}
}

func assertMessageOmits(t *testing.T, label string, message string, forbidden ...string) {
	t.Helper()

	for _, value := range forbidden {
		if value != "" && strings.Contains(message, value) {
			t.Fatalf("%s response leaks queried account identifier %q in %q", label, value, message)
		}
	}
}
