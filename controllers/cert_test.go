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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// certApiTestSetup boots just enough of the app (config + DB connection + an
// in-memory session manager) for ApiController methods to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used by object package tests (see object/user_test.go, which calls
// object.InitConfig() directly against a real database).
var certApiTestSetup sync.Once

func initCertApiTest(t *testing.T) {
	t.Helper()

	certApiTestSetup.Do(func() {
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

// setupCertApiOrgAndUser creates an organization, an application for it (an
// application is required before any user can be added to a non-built-in
// organization), and one signed-in-capable user, registering cleanup for
// all three.
func setupCertApiOrgAndUser(t *testing.T, orgName string) *object.User {
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
	}
	ok, err = object.AddApplication(app)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture application for %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	user := &object.User{
		Owner:       orgName,
		Name:        "admin",
		Id:          orgName + "/admin",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "admin",
		IsAdmin:     true,
	}
	ok, err = object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s: ok=%v err=%v", user.Id, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// callUpdateCertDomainExpire drives ApiController.UpdateCertDomainExpire
// directly, simulating POST /api/update-cert-domain-expire?id=... with the
// given session username (empty means unauthenticated). A panic inside the
// handler (the nil-pointer dereference this test guards against) is
// recovered here so it surfaces as a clear test failure instead of crashing
// the whole test binary.
func callUpdateCertDomainExpire(t *testing.T, sessionUsername, certId string) (resp *Response, panicVal interface{}) {
	t.Helper()

	target := "/api/update-cert-domain-expire?id=" + url.QueryEscape(certId)
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

	if sessionUsername != "" {
		if err := sess.Set(context.Background(), "username", sessionUsername); err != nil {
			t.Fatalf("failed to set session username: %v", err)
		}
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "UpdateCertDomainExpire", nil)

	func() {
		defer func() {
			panicVal = recover()
		}()
		c.UpdateCertDomainExpire()
	}()

	if panicVal != nil {
		return nil, panicVal
	}

	resp = &Response{}
	if err := json.Unmarshal(w.Body.Bytes(), resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), err)
	}
	return resp, nil
}

// TestUpdateCertDomainExpireNonexistentCertDoesNotPanic is the regression
// test for TC-BB92CF6A: an authenticated caller who supplies a cert id that
// does not exist must get a clean JSON error back, not crash the handler
// with a nil-pointer dereference (which, combined with the shipped dev
// runmode, leaks a full beego debug page with stack traces and internal
// file paths). The invariant under test: the domain-expiry update action
// must not crash the server or return an internal stack trace when the
// referenced cert does not exist.
func TestUpdateCertDomainExpireNonexistentCertDoesNotPanic(t *testing.T) {
	initCertApiTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "cert-it-" + suffix
	admin := setupCertApiOrgAndUser(t, orgName)

	nonexistentCertId := orgName + "/does-not-exist-" + suffix

	// Control 1: a malformed id (wrong token count) takes the pre-existing
	// err != nil branch in UpdateCertDomainExpire, which already returns a
	// clean error today. This must keep working unchanged by the fix.
	t.Run("control_malformed_id_returns_clean_error", func(t *testing.T) {
		resp, panicVal := callUpdateCertDomainExpire(t, admin.GetId(), "not-a-valid-id-"+suffix)
		if panicVal != nil {
			t.Fatalf("malformed id crashed the handler: %v", panicVal)
		}
		if resp.Status != "error" {
			t.Fatalf("expected a clean error for a malformed id, got: %+v", resp)
		}
	})

	// Control 2: an unauthenticated caller is rejected by RequireSignedIn
	// before GetCert is ever reached, regardless of the fix. Proves the app
	// is otherwise healthy so the red case below isolates the real bug.
	t.Run("control_unauthenticated_caller_returns_clean_error", func(t *testing.T) {
		resp, panicVal := callUpdateCertDomainExpire(t, "", nonexistentCertId)
		if panicVal != nil {
			t.Fatalf("unauthenticated request crashed the handler: %v", panicVal)
		}
		if resp.Status != "error" {
			t.Fatalf("expected a clean error for an unauthenticated caller, got: %+v", resp)
		}
	})

	// Red/green case: an authenticated caller supplying a well-formed id for
	// a cert that does not exist must not crash the handler.
	t.Run("authenticated_caller_nonexistent_cert_returns_clean_error", func(t *testing.T) {
		resp, panicVal := callUpdateCertDomainExpire(t, admin.GetId(), nonexistentCertId)
		if panicVal != nil {
			t.Fatalf("authenticated request for a nonexistent cert id crashed the handler with a nil-pointer panic instead of returning a clean error (recovered panic: %v)", panicVal)
		}
		if resp.Status != "error" {
			t.Fatalf("expected a clean JSON error for a nonexistent cert id, got: %+v", resp)
		}
		lowerMsg := strings.ToLower(resp.Msg)
		if strings.Contains(lowerMsg, "runtime error") || strings.Contains(lowerMsg, "nil pointer") || strings.Contains(lowerMsg, "goroutine") {
			t.Fatalf("error message leaks internal detail instead of a clean message: %q", resp.Msg)
		}
	})
}
