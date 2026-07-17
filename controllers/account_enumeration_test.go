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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	_ "unsafe"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

//go:linkname testOrmer github.com/casdoor/casdoor/object.ormer
var testOrmer *object.Ormer

//go:linkname testCreateDatabase github.com/casdoor/casdoor/object.createDatabase
var testCreateDatabase bool

func TestUnauthenticatedLoginFailuresDoNotRevealAccountExistence(t *testing.T) {
	setupAccountEnumerationStore(t)

	if _, err := object.CheckUserPassword("acme", "alice", "correct-password", "en"); err != nil {
		t.Fatalf("positive login control failed: %v", err)
	}

	existing := callLogin(t, map[string]string{
		"username":     "alice",
		"password":     "wrong-password",
		"organization": "acme",
		"application":  "app-acme",
		"type":         "login",
	})
	missing := callLogin(t, map[string]string{
		"username":     "missing-alice",
		"password":     "wrong-password",
		"organization": "acme",
		"application":  "app-acme",
		"type":         "login",
	})

	assertIndistinguishableFailure(t, existing, missing)
}

func TestUnauthenticatedVerifyCodeFailuresDoNotRevealAccountExistence(t *testing.T) {
	setupAccountEnumerationStore(t)

	existing := callVerifyCode(t, map[string]string{
		"organization": "acme",
		"username":     "alice@acme.example.com",
		"code":         "000000",
	})
	missing := callVerifyCode(t, map[string]string{
		"organization": "acme",
		"username":     "missing-alice@acme.example.com",
		"code":         "000000",
	})

	assertIndistinguishableFailure(t, existing, missing)
}

func TestUnauthenticatedFaceIDBeginFailuresDoNotRevealAccountExistence(t *testing.T) {
	setupAccountEnumerationStore(t)

	existing := callFaceIDSigninBegin(t, "acme", "alice")
	missing := callFaceIDSigninBegin(t, "acme", "missing-alice")

	assertIndistinguishableFailure(t, existing, missing)
}

func setupAccountEnumerationStore(t *testing.T) {
	t.Helper()

	adapter, err := object.NewAdapter("sqlite", t.TempDir()+"/casdoor-test.db", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		adapter.Engine.Close()
	})
	testOrmer = adapter
	testCreateDatabase = false
	object.CreateTables()

	_, err = object.AddOrganization(&object.Organization{
		Owner:        "admin",
		Name:         "acme",
		PasswordType: "plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = object.AddApplication(&object.Application{
		Owner:                        "admin",
		Name:                         "app-acme",
		Organization:                 "acme",
		EnablePassword:               true,
		EnableCodeSignin:             true,
		FailedSigninLimit:            5,
		FailedSigninFrozenTime:       15,
		SigninMethods:                []*object.SigninMethod{{Name: "Password"}, {Name: "Verification code"}},
		SignupItems:                  []*object.SignupItem{},
		SigninItems:                  []*object.SigninItem{},
		Providers:                    []*object.ProviderItem{},
		GrantTypes:                   []string{},
		EnableSamlPostBinding:        true,
		EnableSamlAssertionSignature: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = object.AddUser(&object.User{
		Owner:             "acme",
		Name:              "alice",
		Type:              "normal-user",
		Password:          "correct-password",
		DisplayName:       "Alice",
		Email:             "alice@acme.example.com",
		SignupApplication: "app-acme",
	}, "en")
	if err != nil {
		t.Fatal(err)
	}
}

func callLogin(t *testing.T, body map[string]string) responseBody {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	return callController(t, req, payload, func(c *ApiController) { c.Login() })
}

func callVerifyCode(t *testing.T, body map[string]string) responseBody {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/verify-code", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	return callController(t, req, payload, func(c *ApiController) { c.VerifyCode() })
}

func callFaceIDSigninBegin(t *testing.T, owner string, name string) responseBody {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/faceid-signin-begin", nil)
	req.URL.RawQuery = url.Values{"owner": {owner}, "name": {name}}.Encode()
	return callController(t, req, nil, func(c *ApiController) { c.FaceIDSigninBegin() })
}

func callController(t *testing.T, req *http.Request, requestBody []byte, fn func(*ApiController)) responseBody {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.RequestBody = requestBody

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", nil)
	fn(controller)

	var body responseBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v; body=%s", err, recorder.Body.String())
	}
	return body
}

type responseBody struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

func assertIndistinguishableFailure(t *testing.T, existing responseBody, missing responseBody) {
	t.Helper()

	if existing.Status != "error" || missing.Status != "error" {
		t.Fatalf("expected both probes to fail, got existing=%+v missing=%+v", existing, missing)
	}
	if existing.Msg != missing.Msg {
		t.Fatalf("responses reveal account existence:\nexisting: %q\nmissing:  %q", existing.Msg, missing.Msg)
	}
	for _, msg := range []string{existing.Msg, missing.Msg} {
		lower := strings.ToLower(msg)
		if strings.Contains(lower, "alice") || strings.Contains(lower, "missing") || strings.Contains(lower, "doesn't exist") || strings.Contains(lower, "remaining chances") {
			t.Fatalf("failure message contains account-specific detail: %q", msg)
		}
	}
}
