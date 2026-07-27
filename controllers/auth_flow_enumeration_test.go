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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestUnauthenticatedAuthFlowErrorsAreIdentifierIndependent(t *testing.T) {
	t.Run("verify code does not distinguish registered emails", func(t *testing.T) {
		registered := runVerifyCode(t, "admin@example.com")
		missing := runVerifyCode(t, "missing-auth-flow-user@example.test")

		if registered.Status != "error" || missing.Status != "error" {
			t.Fatalf("expected both verification failures to return status=error, got registered=%q missing=%q", registered.Status, missing.Status)
		}
		if registered.Msg != missing.Msg {
			t.Fatalf("verification-code response identifies account existence: registered=%q missing=%q", registered.Msg, missing.Msg)
		}
	})

	t.Run("face sign-in begin does not distinguish missing users from users without face data", func(t *testing.T) {
		registered := runFaceIDSigninBegin(t, "admin")
		missing := runFaceIDSigninBegin(t, "missing-auth-flow-user")
		enrollFaceID(t, "admin")
		enrolled := runFaceIDSigninBegin(t, "admin")

		if registered.Status != "error" || missing.Status != "error" {
			t.Fatalf("expected both face sign-in initiation failures to return status=error, got registered=%q missing=%q", registered.Status, missing.Status)
		}
		if enrolled.Status != "ok" {
			t.Fatalf("expected enrolled face sign-in initiation to return status=ok, got status=%q msg=%q", enrolled.Status, enrolled.Msg)
		}
		if registered.Msg != missing.Msg {
			t.Fatalf("face sign-in initiation identifies account/enrollment state: registered=%q missing=%q", registered.Msg, missing.Msg)
		}
	})
}

func runVerifyCode(t *testing.T, username string) *Response {
	t.Helper()

	body := []byte(fmt.Sprintf(`{"organization":"built-in","username":%q,"code":"000000"}`, username))
	req := httptest.NewRequest(http.MethodPost, "/api/verify-code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return runControllerAction(t, req, body, func(c *ApiController) {
		c.VerifyCode()
	})
}

func runFaceIDSigninBegin(t *testing.T, name string) *Response {
	t.Helper()

	query := url.Values{}
	query.Set("owner", "built-in")
	query.Set("name", name)
	req := httptest.NewRequest(http.MethodGet, "/api/faceid-signin-begin?"+query.Encode(), nil)

	return runControllerAction(t, req, nil, func(c *ApiController) {
		c.FaceIDSigninBegin()
	})
}

func enrollFaceID(t *testing.T, name string) {
	t.Helper()

	user, err := object.GetUserByFields("built-in", name)
	if err != nil {
		t.Fatalf("failed to load user for face-id enrollment: %v", err)
	}
	if user == nil {
		t.Fatalf("test user %q does not exist", name)
	}

	user.FaceIds = []*object.FaceId{{Name: "test-face", FaceIdData: []float64{0.1, 0.2, 0.3}}}
	if _, err := object.UpdateUser(user.GetId(), user, []string{"face_ids"}, true); err != nil {
		t.Fatalf("failed to enroll test face id: %v", err)
	}
}

func runControllerAction(t *testing.T, req *http.Request, body []byte, action func(*ApiController)) *Response {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.RequestBody = body

	controller := &ApiController{}
	controller.Init(ctx, "", "", nil)
	action(controller)

	var resp Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response was not JSON: %v; body=%s", err, recorder.Body.String())
	}
	return &resp
}

func TestMain(m *testing.M) {
	dbDir, err := os.MkdirTemp("", "casdoor-auth-flow-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create auth-flow test database directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dbDir)

	os.Setenv("driverName", "sqlite")
	os.Setenv("dataSourceName", filepath.Join(dbDir, "casdoor-auth-flow-test.db"))
	os.Setenv("dbName", "")
	os.Setenv("enableErrorMask2", "false")

	os.Args = append(os.Args, "-config=../conf/app.conf")
	object.InitFlag()
	object.InitConfig()
	object.InitDb()

	os.Exit(m.Run())
}
