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
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/session"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func TestSignupRejectsMismatchedApplicationOrganization(t *testing.T) {
	setupSignupTest(t)

	alphaOrg := newSignupTestOrganization("signup-alpha")
	betaOrg := newSignupTestOrganization("signup-beta")
	alphaApp := newSignupTestApplication(alphaOrg.Name, "app-signup-alpha")
	betaApp := newSignupTestApplication(betaOrg.Name, "app-signup-beta")

	addSignupTestOrganization(t, alphaOrg)
	addSignupTestOrganization(t, betaOrg)
	addSignupTestApplication(t, alphaApp)
	addSignupTestApplication(t, betaApp)

	t.Cleanup(func() {
		_, _ = object.DeleteApplication(alphaApp)
		_, _ = object.DeleteApplication(betaApp)
		_, _ = object.DeleteOrganization(alphaOrg)
		_, _ = object.DeleteOrganization(betaOrg)
	})

	legitimate := postSignup(t, map[string]string{
		"application":  alphaApp.Name,
		"organization": alphaOrg.Name,
		"username":     "legit-signup-user",
		"password":     "Str0ng!TestPass-123",
	})
	if legitimate.Status != "ok" {
		t.Fatalf("matching application/organization signup returned status=%q msg=%q", legitimate.Status, legitimate.Msg)
	}
	if legitimate.Data != alphaOrg.Name+"/legit-signup-user" {
		t.Fatalf("matching signup data = %q, want %q", legitimate.Data, alphaOrg.Name+"/legit-signup-user")
	}

	mismatched := postSignup(t, map[string]string{
		"application":  alphaApp.Name,
		"organization": betaOrg.Name,
		"username":     "cross-signup-user",
		"password":     "Str0ng!TestPass-123",
	})
	if mismatched.Status == "ok" {
		t.Fatalf("mismatched application/organization signup succeeded: %#v", mismatched)
	}

	user, err := object.GetUser(betaOrg.Name + "/cross-signup-user")
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatalf("mismatched signup created user %s", user.GetId())
	}
}

func setupSignupTest(t *testing.T) {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", "file:"+filepath.Join(tempDir, "casdoor.db")+"?cache=shared")
	t.Setenv("dbName", "")

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(".."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatal(err)
		}
	})

	object.InitFlag()
	object.InitAdapter()
	object.CreateTables()
	object.InitDb()
	object.InitUserManager()

	web.GlobalSessions, err = session.NewManager("memory", session.NewManagerConfig())
	if err != nil {
		t.Fatal(err)
	}
	web.BConfig.WebConfig.Session.SessionOn = true
	web.BConfig.WebConfig.Session.SessionProvider = "memory"
	web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"

	web.Router("/api/signup", &ApiController{}, "POST:Signup")
}

func newSignupTestOrganization(name string) *object.Organization {
	return &object.Organization{
		Owner:           "admin",
		Name:            name + "-" + util.GenerateId(),
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     name,
		PasswordType:    "plain",
		PasswordOptions: []string{},
		CountryCodes:    []string{},
		DefaultAvatar:   "",
		AccountItems:    object.GetDefaultAccountItems(),
		InitScore:       2000,
	}
}

func newSignupTestApplication(organization string, name string) *object.Application {
	return &object.Application{
		Owner:          "admin",
		Name:           name + "-" + util.GenerateId(),
		CreatedTime:    util.GetCurrentTime(),
		DisplayName:    name,
		Organization:   organization,
		EnablePassword: true,
		EnableSignUp:   true,
		SignupItems: []*object.SignupItem{
			{Name: "Username", Visible: true, Required: true, Rule: "None"},
			{Name: "Password", Visible: true, Required: true, Rule: "None"},
		},
	}
}

func addSignupTestOrganization(t *testing.T, organization *object.Organization) {
	t.Helper()

	affected, err := object.AddOrganization(organization)
	if err != nil {
		t.Fatal(err)
	}
	if !affected {
		t.Fatalf("failed to add organization %s", organization.Name)
	}
}

func addSignupTestApplication(t *testing.T, application *object.Application) {
	t.Helper()

	affected, err := object.AddApplication(application)
	if err != nil {
		t.Fatal(err)
	}
	if !affected {
		t.Fatalf("failed to add application %s", application.Name)
	}
}

func postSignup(t *testing.T, payload map[string]string) Response {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	web.BeeApp.Handlers.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("/api/signup returned HTTP %d: %s", recorder.Code, recorder.Body.String())
	}

	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, recorder.Body.String())
	}
	return response
}
