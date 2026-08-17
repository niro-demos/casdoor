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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// casLoginTestSetup boots just enough of the app (config + DB connection +
// an in-memory session manager) for ApiController methods to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used by object package tests (see object/user_test.go, which calls
// object.InitConfig() directly against a real database).
var casLoginTestSetup sync.Once

func initCasLoginTest(t *testing.T) {
	t.Helper()

	casLoginTestSetup.Do(func() {
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

// setupCasLoginApp creates an organization plus an application scoped to it
// whose only registered redirect URI is registeredUri, and registers
// cleanup.
func setupCasLoginApp(t *testing.T, orgName, registeredUri string) *object.Application {
	t.Helper()

	org := &object.Organization{
		Owner:       "admin",
		Name:        orgName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: orgName,
	}
	ok, err := object.AddOrganization(org)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture organization %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(org) })

	app := &object.Application{
		Owner:        "admin",
		Name:         "app-" + orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "app-" + orgName,
		Organization: orgName,
		RedirectUris: []string{registeredUri},
	}
	ok, err = object.AddApplication(app)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture application for %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	fullApp, err := object.GetApplication(app.GetId())
	if err != nil || fullApp == nil {
		t.Fatalf("failed to reload fixture application %s: err=%v", app.GetId(), err)
	}
	return fullApp
}

// setupCasLoginUser creates a user in orgName and registers cleanup.
func setupCasLoginUser(t *testing.T, orgName, name string) *object.User {
	t.Helper()

	user := &object.User{
		Owner:       orgName,
		Name:        name,
		Id:          orgName + "/" + name,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: name,
	}
	ok, err := object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s/%s: ok=%v err=%v", orgName, name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// casLogin drives ApiController.HandleLoggedIn directly with an authForm of
// type "cas" and the given service query parameter -- the same seam
// (Login -> HandleLoggedIn's ResponseTypeCas branch) that issues the CAS
// service ticket in production, bypassing only password verification (not
// under test here; see the RedirectUris allow-list assertion below).
func casLogin(t *testing.T, application *object.Application, user *object.User, service string) *Response {
	t.Helper()

	target := "/api/login?" + url.Values{"service": {service}}.Encode()
	req := httptest.NewRequest(http.MethodPost, target, nil)
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
	c.Init(ctx, "ApiController", "Login", nil)

	authForm := &form.AuthForm{Type: "cas", Organization: application.Organization, Application: application.Name}
	resp := c.HandleLoggedIn(application, user, authForm)
	if resp == nil {
		t.Fatalf("HandleLoggedIn returned nil response (an early guard rejected the fixture user/application): body=%q", w.Body.String())
	}
	return resp
}

// TestCasLoginRejectsUnregisteredService is the regression test for
// TC-A303B9EA: a CAS login ticket must only be issued for a service URL the
// target application has actually registered as an allowed redirect URI --
// not for an arbitrary, attacker-chosen URL supplied at login time.
func TestCasLoginRejectsUnregisteredService(t *testing.T) {
	initCasLoginTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "cas-login-it-" + suffix
	registeredUri := "http://localhost:19001/callback"

	application := setupCasLoginApp(t, orgName, registeredUri)
	alice := setupCasLoginUser(t, orgName, "alice")

	t.Run("unregistered_service_rejected", func(t *testing.T) {
		unregisteredService := "https://evil.example.com/" + suffix
		resp := casLogin(t, application, alice, unregisteredService)
		if resp.Status == "ok" {
			t.Fatalf("CAS login ticket was issued for an unregistered service URL %q not in the application's RedirectUris %v: %+v",
				unregisteredService, application.RedirectUris, resp)
		}
	})

	// Positive control: the same flow using the actually-registered redirect
	// URI must keep working end-to-end, proving the rejection above is the
	// missing allow-list check, not a broken fixture/environment.
	t.Run("registered_service_allowed", func(t *testing.T) {
		resp := casLogin(t, application, alice, registeredUri)
		if resp.Status != "ok" {
			t.Fatalf("control failed: CAS login against the application's registered redirect URI %q was rejected: %+v", registeredUri, resp)
		}
		ticket, ok := resp.Data.(string)
		if !ok || ticket == "" {
			t.Fatalf("control failed: CAS login against the registered redirect URI did not return a service ticket: %+v", resp)
		}
	})
}
