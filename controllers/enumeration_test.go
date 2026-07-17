// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"testing"
	"time"

	beegoCtx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// callController drives a controller method directly through beego's
// context plumbing (the same Init/Reset sequence the router itself uses),
// without needing to bind a real port or register the full route table.
func callController(t *testing.T, method, target string, body []byte, contentType string, action func(c *ApiController)) Response {
	t.Helper()

	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()

	ctx := beegoCtx.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "", nil)

	action(c)

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response was not valid JSON (body=%s): %v", w.Body.String(), err)
	}
	return resp
}

// formURLEncodedBody builds an application/x-www-form-urlencoded body.
// (The verified PoC used multipart/form-data over the wire, but driving the
// controller directly — bypassing beego's own router/multipart-parsing
// middleware — needs a body shape Go's stdlib http.Request.ParseForm()
// understands; the encoding is not part of the invariant under test, only
// the resulting VerificationForm field values are.)
func formURLEncodedBody(fields map[string]string) ([]byte, string) {
	values := url.Values{}
	for k, v := range fields {
		values.Set(k, v)
	}
	return []byte(values.Encode()), "application/x-www-form-urlencoded"
}

// TestPreAuthEndpointsDoNotLeakUsernameExistence guards against TC-6CB8F4A3:
// GET /api/webauthn/signin/begin, GET /api/faceid-signin-begin, and
// POST /api/send-verification-code must respond identically to a real,
// registered username and to a fabricated, guaranteed-nonexistent one — an
// unauthenticated caller must not be able to use the response body to tell
// whether an owner/name pair exists.
func TestPreAuthEndpointsDoNotLeakUsernameExistence(t *testing.T) {
	object.InitConfig()
	object.InitDb()
	object.InitUserManager()

	suffix := time.Now().UnixNano()
	orgName := fmt.Sprintf("niro_enum_org_%d", suffix)
	appName := fmt.Sprintf("niro-enum-app-%d", suffix)
	realUserName := fmt.Sprintf("niro-real-user-%d", suffix)
	ghostUserName := fmt.Sprintf("niro-ghost-user-%d", suffix)

	org := &object.Organization{Owner: "admin", Name: orgName}
	if ok, err := object.AddOrganization(org); err != nil || !ok {
		t.Fatalf("failed to create fixture organization: ok=%v err=%v", ok, err)
	}
	defer object.DeleteOrganization(org)

	app := &object.Application{Owner: "admin", Name: appName, Organization: orgName}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("failed to create fixture application: ok=%v err=%v", ok, err)
	}
	defer object.DeleteApplication(app)

	realUser := &object.User{
		Owner:    orgName,
		Name:     realUserName,
		Email:    fmt.Sprintf("%s@example.com", realUserName),
		Password: "Niro-Test-Pw-1!",
	}
	if ok, err := object.AddUser(realUser, "en"); err != nil || !ok {
		t.Fatalf("failed to create fixture user: ok=%v err=%v", ok, err)
	}
	defer object.DeleteUser(realUser)

	// --- Probe 1: GET /api/webauthn/signin/begin ---
	realWebauthn := callController(t, http.MethodGet,
		fmt.Sprintf("/api/webauthn/signin/begin?owner=%s&name=%s", orgName, realUserName), nil, "",
		func(c *ApiController) { c.WebAuthnSigninBegin() })
	ghostWebauthn := callController(t, http.MethodGet,
		fmt.Sprintf("/api/webauthn/signin/begin?owner=%s&name=%s", orgName, ghostUserName), nil, "",
		func(c *ApiController) { c.WebAuthnSigninBegin() })

	if realWebauthn.Msg != ghostWebauthn.Msg {
		t.Errorf("SECURITY REGRESSION (TC-6CB8F4A3): GET /api/webauthn/signin/begin distinguishes account existence — real user msg=%q, ghost user msg=%q",
			realWebauthn.Msg, ghostWebauthn.Msg)
	}

	// --- Probe 2: GET /api/faceid-signin-begin ---
	realFace := callController(t, http.MethodGet,
		fmt.Sprintf("/api/faceid-signin-begin?owner=%s&name=%s", orgName, realUserName), nil, "",
		func(c *ApiController) { c.FaceIDSigninBegin() })
	ghostFace := callController(t, http.MethodGet,
		fmt.Sprintf("/api/faceid-signin-begin?owner=%s&name=%s", orgName, ghostUserName), nil, "",
		func(c *ApiController) { c.FaceIDSigninBegin() })

	if realFace.Msg != ghostFace.Msg {
		t.Errorf("SECURITY REGRESSION (TC-6CB8F4A3): GET /api/faceid-signin-begin distinguishes account existence — real user msg=%q, ghost user msg=%q",
			realFace.Msg, ghostFace.Msg)
	}

	// --- Probe 3: POST /api/send-verification-code ---
	// type=login (neither "email" nor "phone") makes the handler fall through
	// to its generic "invalid dest type" branch for any resolved user,
	// without actually sending a verification code — same technique the
	// verified PoC used to reproduce the oracle side-effect-free.
	realBody, ct := formURLEncodedBody(map[string]string{
		"captchaType":   "none",
		"method":        "login",
		"type":          "login",
		"dest":          "real@example.com",
		"applicationId": fmt.Sprintf("admin/%s", appName),
		"checkUser":     realUserName,
	})
	realCode := callController(t, http.MethodPost, "/api/send-verification-code", realBody, ct,
		func(c *ApiController) { c.SendVerificationCode() })

	ghostBody, ct2 := formURLEncodedBody(map[string]string{
		"captchaType":   "none",
		"method":        "login",
		"type":          "login",
		"dest":          "ghost@example.com",
		"applicationId": fmt.Sprintf("admin/%s", appName),
		"checkUser":     ghostUserName,
	})
	ghostCode := callController(t, http.MethodPost, "/api/send-verification-code", ghostBody, ct2,
		func(c *ApiController) { c.SendVerificationCode() })

	if realCode.Msg != ghostCode.Msg {
		t.Errorf("SECURITY REGRESSION (TC-6CB8F4A3): POST /api/send-verification-code distinguishes account existence — real user msg=%q, ghost user msg=%q",
			realCode.Msg, ghostCode.Msg)
	}
}
