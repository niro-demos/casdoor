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

// casTestSetup boots just enough of the app (config + DB connection) for
// RootController methods to be invoked directly, bypassing the HTTP
// router/filters -- the same style of DB-backed setup used by object package
// tests (see object/user_test.go, which calls object.InitConfig() directly
// against a real database).
var casTestSetup sync.Once

func initCasTest(t *testing.T) {
	t.Helper()

	casTestSetup.Do(func() {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			panic("failed to resolve test file path")
		}
		repoRoot := filepath.Dir(filepath.Dir(thisFile))

		// Loads conf/app.conf (real MySQL DSN), mirroring what main.go does
		// at startup.
		web.TestBeegoInit(repoRoot)

		object.InitAdapter()
		object.CreateTables()
		object.InitDb()
		object.InitUserManager()
	})
}

// setupCasTestOrgAndUser creates an organization, one application for it (an
// application is required before any user can be added to a non-built-in
// organization), and a user within it, registering cleanup for all three.
func setupCasTestOrgAndUser(t *testing.T, orgName, userName string) *object.User {
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
		Name:        userName,
		Id:          orgName + "/" + userName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: userName,
	}
	ok, err = object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s/%s: ok=%v err=%v", orgName, userName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// callCasServiceValidate drives (*RootController).CasP3ProxyValidate directly
// -- the shared implementation backing the serviceValidate, proxyValidate,
// p3/serviceValidate, and p3/proxyValidate CAS endpoints -- with the given
// ticket and service, and returns the raw XML response body.
func callCasServiceValidate(t *testing.T, ticket, service string) string {
	t.Helper()

	target := fmt.Sprintf("/cas/serviceValidate?ticket=%s&service=%s", url.QueryEscape(ticket), url.QueryEscape(service))
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(w, req)

	c := &RootController{}
	c.Init(ctx, "RootController", "CasP3ProxyValidate", nil)
	c.CasP3ProxyValidate()

	return w.Body.String()
}

func isCasSuccess(body string) bool {
	return strings.Contains(body, "cas:authenticationSuccess")
}

func isCasInvalidService(body string) bool {
	return strings.Contains(body, "cas:authenticationFailure") && strings.Contains(body, `code="INVALID_SERVICE"`)
}

// TestCasServiceValidateRejectsPrefixMatchService is the regression test for
// TC-9454980F. The invariant under test: CAS ticket validation must confirm
// the validating party's service URL exactly matches the service the ticket
// was originally issued for, not merely that one string starts with the
// other. A ticket issued for https://good.example.com must not validate for
// https://good.example.com.attacker.net/steal, which merely has the
// registered service as a string prefix but is a different host entirely.
func TestCasServiceValidateRejectsPrefixMatchService(t *testing.T) {
	initCasTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "cas-it-" + suffix
	user := setupCasTestOrgAndUser(t, orgName, "bob")

	legitimateService := "https://good.example.com"
	unrelatedService := "https://totally-unrelated.example.org"
	attackerService := "https://good.example.com.attacker.net/steal"

	newTicket := func() string {
		ticket, err := object.GenerateCasToken(user.GetId(), legitimateService)
		if err != nil {
			t.Fatalf("failed to issue CAS ticket: %v", err)
		}
		return ticket
	}

	// Positive control: exact match must succeed, proving the ticket
	// lookup and the harness work before we test the invariant.
	t.Run("exact_match_service_allowed", func(t *testing.T) {
		body := callCasServiceValidate(t, newTicket(), legitimateService)
		if !isCasSuccess(body) {
			t.Fatalf("control failed: exact-match service was rejected: %s", body)
		}
	})

	// Negative control: a wholly unrelated service (not even a prefix
	// relation) must be rejected, proving denial isn't just always-false.
	t.Run("unrelated_service_rejected", func(t *testing.T) {
		body := callCasServiceValidate(t, newTicket(), unrelatedService)
		if !isCasInvalidService(body) {
			t.Fatalf("control failed: totally unrelated service was accepted: %s", body)
		}
	})

	// The exploit: a service URL that merely starts with the registered
	// service string, but is a different host, must be rejected.
	t.Run("prefix_match_attacker_service_rejected", func(t *testing.T) {
		body := callCasServiceValidate(t, newTicket(), attackerService)
		if isCasSuccess(body) {
			t.Fatalf("INVARIANT VIOLATED: ticket issued for %q validated successfully for attacker service %q via prefix match: %s",
				legitimateService, attackerService, body)
		}
		if !isCasInvalidService(body) {
			t.Fatalf("expected INVALID_SERVICE failure for attacker service, got: %s", body)
		}
	})
}
