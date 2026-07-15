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
	"net/http/httptest"
	"net/url"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/object"
)

// newHandleLoggedInController wires an ApiController to a request carrying
// the given raw query string (HandleLoggedIn reads "service" straight off
// the query string) and a loopback RemoteAddr, so object.CheckEntryIp's
// existing loopback short-circuit (object/check_ip.go) is exercised rather
// than bypassed by a mock.
func newHandleLoggedInController(rawQuery string) *ApiController {
	req := httptest.NewRequest("POST", "http://localhost:8000/api/login?"+rawQuery, nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(rec, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "Login", c)
	return c
}

// TestHandleLoggedIn_CasTicketRequiresRegisteredService is the regression
// test for TC-D18FAECF: HandleLoggedIn's CAS ticket-granting branch must
// refuse to mint a service ticket for a "service" that is not one of the
// target application's registered RedirectUris, exactly as
// GetApplicationLogin already requires via object.CheckCasLogin.
//
// The user is given owner "built-in" so that the pre-existing, DB-free
// short-circuits already in the production code path are exercised for
// real, without needing a live database for this test:
//   - object.User.IsGlobalAdmin (object/user.go) treats owner=="built-in" as
//     global admin, which -- combined with an empty application.Tags --
//     skips the tag check without a query.
//   - object.CheckLoginPermission (object/check.go) returns (true, nil) for
//     owner=="built-in" without a query.
//   - object.CheckEntryIp (object/check_ip.go) short-circuits to nil for a
//     loopback client IP without a query.
//
// On the current (unfixed) code, an unregistered service is never checked
// against application.RedirectUris at all: HandleLoggedIn proceeds straight
// to object.GenerateCasToken, which calls object.GetUser and therefore does
// need the database -- with none configured in this test binary, that call
// panics. That panic is itself evidence the guard did not stop the
// ticket-granting path, so it is captured (not left to crash the suite) and
// treated as the vulnerable outcome, on par with an unguarded "ok" response.
func TestHandleLoggedIn_CasTicketRequiresRegisteredService(t *testing.T) {
	application := &object.Application{
		Owner:        "acme",
		Name:         "app-acme",
		RedirectUris: []string{"http://localhost:8000/callback"},
	}
	user := &object.User{
		Owner: "built-in",
		Name:  "alice",
		Type:  "normal-user",
	}
	authForm := &form.AuthForm{Type: ResponseTypeCas}

	attackerService := "http://evil.attacker.example/steal"
	c := newHandleLoggedInController("service=" + url.QueryEscape(attackerService))

	var resp *Response
	func() {
		defer func() {
			if r := recover(); r != nil {
				resp = &Response{Status: "ok", Msg: fmt.Sprintf("reached ticket generation and panicked reaching the database: %v", r)}
			}
		}()
		resp = c.HandleLoggedIn(application, user, authForm)
	}()

	if resp.Status == "ok" {
		t.Fatalf("invariant violated: a CAS ticket-granting request for service %q, which is NOT in application %q's registered RedirectUris %v, was not rejected before minting/attempting to mint a ticket (resp=%+v)",
			attackerService, application.GetId(), application.RedirectUris, resp)
	}
}

// TestHandleLoggedIn_CasServiceGuardAcceptsRegisteredService is the positive
// control: object.CheckCasLogin (the guard the fix wires into
// HandleLoggedIn) must not reject the application's own registered
// redirect URI. This isolates "the guard itself works" from the
// database-dependent full ticket-issuance flow exercised above.
func TestHandleLoggedIn_CasServiceGuardAcceptsRegisteredService(t *testing.T) {
	application := &object.Application{
		Owner:        "acme",
		Name:         "app-acme",
		RedirectUris: []string{"http://localhost:8000/callback"},
	}

	if err := object.CheckCasLogin(application, "en", "http://localhost:8000/callback"); err != nil {
		t.Fatalf("environment unhealthy: the application's own registered redirect URI was rejected by CheckCasLogin: %v", err)
	}
}
