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
	"os"
	"path/filepath"
	"sync"
	"testing"

	beegoctx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

var setupAccountEnumerationTestDbOnce sync.Once

func setupAccountEnumerationTestDb(t *testing.T) {
	t.Helper()

	setupAccountEnumerationTestDbOnce.Do(func() {
		tempDir, err := os.MkdirTemp("", "casdoor-account-enumeration-test-*")
		if err != nil {
			t.Fatal(err)
		}

		dbPath := filepath.Join(tempDir, "casdoor-account-enumeration-test.db")
		if err := os.Setenv("driverName", "sqlite"); err != nil {
			t.Fatal(err)
		}
		if err := os.Setenv("dataSourceName", "file:"+dbPath+"?cache=shared"); err != nil {
			t.Fatal(err)
		}
		if err := os.Setenv("dbName", ""); err != nil {
			t.Fatal(err)
		}

		oldArgs := os.Args
		os.Args = []string{oldArgs[0], "-config", "../conf/app.conf"}
		object.InitFlag()
		os.Args = oldArgs
		object.InitConfig()
		object.InitDb()
	})
}

func TestLoginInvalidCredentialsDoNotRevealAccountExistence(t *testing.T) {
	setupAccountEnumerationTestDb(t)

	existing := callAPIController(t, http.MethodPost, "/api/login", map[string]string{
		"application":  "app-built-in",
		"organization": "built-in",
		"username":     "admin",
		"password":     "wrong-password",
		"signinMethod": "Password",
		"type":         "login",
	}, (*ApiController).Login)
	missing := callAPIController(t, http.MethodPost, "/api/login", map[string]string{
		"application":  "app-built-in",
		"organization": "built-in",
		"username":     "this-user-does-not-exist",
		"password":     "wrong-password",
		"signinMethod": "Password",
		"type":         "login",
	}, (*ApiController).Login)

	if existing.Status != "error" {
		t.Fatalf("existing-user invalid login status = %q, want error (msg=%q)", existing.Status, existing.Msg)
	}
	if missing.Status != "error" {
		t.Fatalf("missing-user invalid login status = %q, want error (msg=%q)", missing.Status, missing.Msg)
	}
	if existing.Msg != missing.Msg {
		t.Fatalf("invalid login distinguishes account existence: existing msg %q, missing msg %q", existing.Msg, missing.Msg)
	}
}

func TestFaceIDSigninBeginDoesNotRevealAccountExistence(t *testing.T) {
	setupAccountEnumerationTestDb(t)

	existing := callAPIController(t, http.MethodGet, "/api/faceid-signin-begin?owner=built-in&name=admin", nil, (*ApiController).FaceIDSigninBegin)
	missing := callAPIController(t, http.MethodGet, "/api/faceid-signin-begin?owner=built-in&name=this-user-does-not-exist", nil, (*ApiController).FaceIDSigninBegin)

	if existing.Status != missing.Status || existing.Msg != missing.Msg {
		t.Fatalf("FaceID begin distinguishes account existence: existing status=%q msg=%q, missing status=%q msg=%q", existing.Status, existing.Msg, missing.Status, missing.Msg)
	}
}

func callAPIController(t *testing.T, method string, target string, body any, handler func(*ApiController)) Response {
	t.Helper()

	var requestBody []byte
	if body != nil {
		var err error
		requestBody, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(method, target, bytes.NewReader(requestBody))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	ctx := beegoctx.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.RequestBody = requestBody

	controller := &ApiController{}
	controller.Init(ctx, "", "", nil)
	handler(controller)

	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return response
}
