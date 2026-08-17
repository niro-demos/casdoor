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

//go:build !skipCi

package controllers_test

import (
	"bytes"
	gocontext "context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beegoctx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
)

// This test covers TC-0A339A83: the self-service signup endpoint
// (POST /api/signup) must only be able to create a new user inside the
// organization that the named application actually belongs to, not an
// arbitrary other organization picked independently by the caller.
//
// It asserts the invariant with a paired legitimate control: signing up
// through an application into its *own* organization must keep succeeding
// (so the fix doesn't break normal signup), while signing up through that
// same application into an unrelated organization must be rejected and must
// not plant a user there.

// appConfPath resolves the repository's conf/app.conf regardless of the
// test binary's working directory, mirroring object.InitConfig()'s reliance
// on being run from a package directory one level below the repo root.
func appConfPath(t *testing.T) string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine test file location")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "conf", "app.conf")
}

// signupResponse mirrors controllers.Response's JSON shape for decoding.
type signupResponse struct {
	Status string      `json:"status"`
	Msg    string      `json:"msg"`
	Data   interface{} `json:"data"`
}

// doSignup drives the real ApiController.Signup() handler in-process,
// exactly as the router would dispatch a POST /api/signup request, without
// requiring a live network listener.
func doSignup(t *testing.T, application, organization, username, password string) signupResponse {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"application": application,
		"organization": organization,
		"username":     username,
		"password":     password,
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/signup", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ctx := beegoctx.NewContext()
	ctx.Reset(w, r)
	// Mimic routers.RequestBodyFilter, which caches the raw body on
	// ctx.Input.RequestBody before Signup() reads it.
	ctx.Input.RequestBody = body

	session, err := web.GlobalSessions.SessionStart(w, r)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	defer session.SessionRelease(gocontext.Background(), w)
	ctx.Input.CruSession = session

	c := &controllers.ApiController{}
	c.Init(ctx, "ApiController", "Signup", nil)
	c.Prepare()
	c.Signup()
	c.Finish()

	var resp signupResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode signup response %q: %v", w.Body.String(), err)
	}
	return resp
}

// minimalSignupItems only asks for what this test's requests actually send,
// so Signup() doesn't block on unrelated required fields (Email, Phone,
// Display name, ...).
func minimalSignupItems() []*object.SignupItem {
	return []*object.SignupItem{
		{Name: "ID", Visible: false, Required: true, Prompted: false, Rule: "Random"},
		{Name: "Username", Visible: true, Required: true, Prompted: false, Rule: "None"},
		{Name: "Password", Visible: true, Required: true, Prompted: false, Rule: "None"},
		{Name: "Confirm password", Visible: true, Required: true, Prompted: false, Rule: "None"},
	}
}

func TestSignupRejectsApplicationOrganizationMismatch(t *testing.T) {
	object.InitConfig()
	// Mirrors main.go's own bootstrap order: InitDb() seeds the built-in
	// model/adapter/enforcer rows that InitUserManager() (and in turn
	// object.DeleteUser's group cleanup, used below) requires.
	object.InitDb()
	object.InitUserManager()
	web.InitBeegoBeforeTest(appConfPath(t))

	stamp := time.Now().UnixNano()
	orgAName := "tc0a339a83-org-a"
	orgBName := "tc0a339a83-org-b"
	appAName := "tc0a339a83-app-a"
	appBName := "tc0a339a83-app-b"

	orgA := &object.Organization{
		Owner:         "admin",
		Name:          orgAName,
		CreatedTime:   "2026-01-01T00:00:00Z",
		DisplayName:   "TC-0A339A83 org A",
		PasswordType:  "plain",
		InitScore:     0,
		DefaultAvatar: "https://example.com/avatar.png",
	}
	orgB := &object.Organization{
		Owner:         "admin",
		Name:          orgBName,
		CreatedTime:   "2026-01-01T00:00:00Z",
		DisplayName:   "TC-0A339A83 org B",
		PasswordType:  "plain",
		InitScore:     0,
		DefaultAvatar: "https://example.com/avatar.png",
	}
	appA := &object.Application{
		Owner:          "admin",
		Name:           appAName,
		CreatedTime:    "2026-01-01T00:00:00Z",
		DisplayName:    "TC-0A339A83 app A",
		Organization:   orgAName,
		EnablePassword: true,
		EnableSignUp:   true,
		SignupItems:    minimalSignupItems(),
	}
	// org B owns its own application, exactly like the live finding's
	// niro-beta/app-niro-beta: this proves org B is a normal, fully usable
	// organization, so the rejection below can only be explained by the
	// app A / org B mismatch, not by org B lacking any application at all.
	appB := &object.Application{
		Owner:          "admin",
		Name:           appBName,
		CreatedTime:    "2026-01-01T00:00:00Z",
		DisplayName:    "TC-0A339A83 app B",
		Organization:   orgBName,
		EnablePassword: true,
		EnableSignUp:   true,
		SignupItems:    minimalSignupItems(),
	}

	cleanupUser := func(owner, name string) {
		user, _ := object.GetUser(owner + "/" + name)
		if user != nil {
			_, _ = object.DeleteUser(user)
		}
	}

	// Setup: org A, org B, and one application that belongs only to org A.
	if ok, err := object.AddOrganization(orgA); err != nil || !ok {
		t.Fatalf("setup: AddOrganization(orgA) failed: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = object.DeleteOrganization(orgA) }()

	if ok, err := object.AddOrganization(orgB); err != nil || !ok {
		t.Fatalf("setup: AddOrganization(orgB) failed: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = object.DeleteOrganization(orgB) }()

	if ok, err := object.AddApplication(appA); err != nil || !ok {
		t.Fatalf("setup: AddApplication(appA) failed: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = object.DeleteApplication(appA) }()

	if ok, err := object.AddApplication(appB); err != nil || !ok {
		t.Fatalf("setup: AddApplication(appB) failed: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = object.DeleteApplication(appB) }()

	stampStr := strconv.FormatInt(stamp, 36)

	// --- Control: legitimate same-organization signup must keep succeeding ---
	legitUser := "sutestlegit" + stampStr
	defer cleanupUser(orgAName, legitUser)

	controlResp := doSignup(t, appAName, orgAName, legitUser, "ScoutPass123!")
	if controlResp.Status != "ok" {
		t.Fatalf("legitimate same-org signup should succeed, got status=%q msg=%q (environment unhealthy, cannot trust the attack case below)",
			controlResp.Status, controlResp.Msg)
	}
	if createdUser, err := object.GetUser(orgAName + "/" + legitUser); err != nil {
		t.Fatalf("GetUser(orgA legit user) error: %v", err)
	} else if createdUser == nil {
		t.Fatalf("legitimate signup reported success but no user was created under org %q", orgAName)
	}

	// --- Attack: cross-tenant signup must be rejected ---
	crossTenantUser := "sutestcross" + stampStr
	defer cleanupUser(orgBName, crossTenantUser)

	exploitResp := doSignup(t, appAName, orgBName, crossTenantUser, "ScoutPass123!")
	if exploitResp.Status == "ok" {
		t.Fatalf("VIOLATION: signup through app %q (belonging to org %q) planted a user into unrelated org %q (data=%v)",
			appAName, orgAName, orgBName, exploitResp.Data)
	}

	planted, err := object.GetUser(orgBName + "/" + crossTenantUser)
	if err != nil {
		t.Fatalf("GetUser(orgB cross-tenant user) error: %v", err)
	}
	if planted != nil {
		t.Fatalf("VIOLATION: user %q was created under unrelated org %q despite the rejected response", crossTenantUser, orgBName)
	}
}
