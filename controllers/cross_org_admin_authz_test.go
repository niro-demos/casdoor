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

package controllers

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	beegoCtx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// newTestApiController builds an ApiController wired to a real (but
// fabricated) Beego context/session-free request, exactly like ApiFilter
// does at runtime (it stashes the authenticated user id into
// ctx.Input.SetData("currentUserId", ...)) - so the controller methods
// under test run their real authorization logic, not a mock.
func newTestApiController(t *testing.T, method, target, sessionUserId string) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()

	ctx := beegoCtx.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "", nil)

	if sessionUserId != "" {
		ctx.Input.SetData("currentUserId", sessionUserId)
	}

	return c, w
}

func decodeControllerResponse(t *testing.T, w *httptest.ResponseRecorder) *Response {
	t.Helper()

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode controller response %q: %v", w.Body.String(), err)
	}
	return &resp
}

// TestOrgScopedAdminCannotReadAnotherOrgsCommerceData is the regression test
// for TC-BAFE51C7: an org-scoped admin (IsAdmin == true, Owner != "built-in")
// must not be able to read another organization's transactions, orders, or
// payments by passing that organization's owner/id in the query string.
//
// c.IsAdmin() returns true for ANY admin, global or org-scoped, with no
// comparison against the target resource's owner - that conflation is the
// root cause (controllers/base.go). GetTransactions, GetOrders, GetOrder and
// GetPayment all gated cross-tenant reads on IsAdmin() alone.
func TestOrgScopedAdminCannotReadAnotherOrgsCommerceData(t *testing.T) {
	object.InitConfig()
	object.InitUserManager()

	suffix := util.GenerateId()
	ownOrg := "authz-test-own-" + suffix
	victimOrg := "authz-test-victim-" + suffix
	adminName := "org-admin-" + suffix
	sessionUserId := ownOrg + "/" + adminName

	// Seed an org-scoped admin (IsAdmin == true) belonging to ownOrg, never
	// to victimOrg or "built-in". AddUsers is the syncer/batch-insert path
	// and, unlike AddUser, does not require an Organization/Application row
	// to already exist - fine here since none of the authorization logic
	// under test reads the Organization/Application tables.
	adminUser := &object.User{
		Owner:   ownOrg,
		Name:    adminName,
		Id:      util.GenerateId(),
		IsAdmin: true,
	}
	if ok, err := object.AddUsers([]*object.User{adminUser}); err != nil || !ok {
		t.Fatalf("failed to seed org-scoped admin user: ok=%v err=%v", ok, err)
	}
	defer object.DeleteUser(adminUser)

	// Seed one order, payment and transaction owned by a DIFFERENT
	// organization ("victimOrg") that the admin above must never be able
	// to read.
	victimOrder := &object.Order{Owner: victimOrg, Name: "victim-order-" + suffix, User: "victim-user"}
	if ok, err := object.AddOrder(victimOrder); err != nil || !ok {
		t.Fatalf("failed to seed victim order: ok=%v err=%v", ok, err)
	}
	defer object.DeleteOrder(victimOrder)

	victimPayment := &object.Payment{Owner: victimOrg, Name: "victim-payment-" + suffix, User: "victim-user"}
	if ok, err := object.AddPayment(victimPayment); err != nil || !ok {
		t.Fatalf("failed to seed victim payment: ok=%v err=%v", ok, err)
	}
	defer object.DeletePayment(victimPayment)

	victimTransaction := &object.Transaction{Owner: victimOrg, User: "victim-user", Amount: 1}
	if ok, _, err := object.AddTransaction(victimTransaction, "en", false); err != nil || !ok {
		t.Fatalf("failed to seed victim transaction: ok=%v err=%v", ok, err)
	}
	defer object.DeleteTransaction(victimTransaction, "en")

	t.Run("GetTransactions must not disclose another org's transactions", func(t *testing.T) {
		c, w := newTestApiController(t, "GET", "/api/get-transactions?owner="+victimOrg, sessionUserId)
		c.GetTransactions()
		resp := decodeControllerResponse(t, w)
		if resp.Status == "ok" {
			t.Fatalf("invariant violated: org-scoped admin of %q read %q's transactions: %s", ownOrg, victimOrg, w.Body.String())
		}
	})

	t.Run("GetOrders must not disclose another org's orders", func(t *testing.T) {
		c, w := newTestApiController(t, "GET", "/api/get-orders?owner="+victimOrg, sessionUserId)
		c.GetOrders()
		resp := decodeControllerResponse(t, w)
		if resp.Status == "ok" {
			t.Fatalf("invariant violated: org-scoped admin of %q read %q's orders: %s", ownOrg, victimOrg, w.Body.String())
		}
	})

	t.Run("GetOrder must not disclose another org's order by id", func(t *testing.T) {
		c, w := newTestApiController(t, "GET", "/api/get-order?id="+victimOrg+"/"+victimOrder.Name, sessionUserId)
		c.GetOrder()
		resp := decodeControllerResponse(t, w)
		if resp.Status == "ok" {
			t.Fatalf("invariant violated: org-scoped admin of %q read %q's order by id: %s", ownOrg, victimOrg, w.Body.String())
		}
	})

	t.Run("GetPayment must not disclose another org's payment by id", func(t *testing.T) {
		c, w := newTestApiController(t, "GET", "/api/get-payment?id="+victimOrg+"/"+victimPayment.Name, sessionUserId)
		c.GetPayment()
		resp := decodeControllerResponse(t, w)
		if resp.Status == "ok" {
			t.Fatalf("invariant violated: org-scoped admin of %q read %q's payment by id: %s", ownOrg, victimOrg, w.Body.String())
		}
	})

	// Controls: the SAME org-scoped admin reading their OWN org's data must
	// keep working - this proves the fix denies cross-org access without
	// breaking the legitimate same-org admin path.
	t.Run("control: GetOrders still returns the admin's own org", func(t *testing.T) {
		ownOrder := &object.Order{Owner: ownOrg, Name: "own-order-" + suffix, User: "own-user"}
		if ok, err := object.AddOrder(ownOrder); err != nil || !ok {
			t.Fatalf("failed to seed own-org order: ok=%v err=%v", ok, err)
		}
		defer object.DeleteOrder(ownOrder)

		c, w := newTestApiController(t, "GET", "/api/get-orders?owner="+ownOrg, sessionUserId)
		c.GetOrders()
		resp := decodeControllerResponse(t, w)
		if resp.Status != "ok" {
			t.Fatalf("own-org admin read was unexpectedly denied: %s", w.Body.String())
		}
	})
}

// TestOrgScopedAdminCannotReadAnotherOrgsApplications is the regression test
// for TC-44A41C6A: an org-scoped admin (Owner != "built-in", IsAdmin == true)
// must not be able to read another organization's application configuration
// via GET /api/get-organization-applications.
//
// object.GetAllowedApplications special-cased user.IsAdmin and returned
// every application in the requested organization without checking that the
// caller's Owner matched that organization (or application.IsShared) -
// unlike the one existing per-application check for exactly this purpose,
// User.IsApplicationAdmin (object/user.go).
func TestOrgScopedAdminCannotReadAnotherOrgsApplications(t *testing.T) {
	object.InitConfig()
	object.InitUserManager()

	suffix := util.GenerateId()
	ownOrg := "authz-test-app-own-" + suffix
	victimOrg := "authz-test-app-victim-" + suffix
	adminName := "org-app-admin-" + suffix
	sessionUserId := ownOrg + "/" + adminName

	adminUser := &object.User{
		Owner:   ownOrg,
		Name:    adminName,
		Id:      util.GenerateId(),
		IsAdmin: true,
	}
	if ok, err := object.AddUsers([]*object.User{adminUser}); err != nil || !ok {
		t.Fatalf("failed to seed org-scoped admin user: ok=%v err=%v", ok, err)
	}
	defer object.DeleteUser(adminUser)

	// An application belonging to a DIFFERENT organization, not shared.
	victimApp := &object.Application{
		Owner:        "admin",
		Name:         "victim-app-" + suffix,
		Organization: victimOrg,
		DisplayName:  "victim app",
		ClientId:     "authz-test-client-" + suffix,
		ClientSecret: "authz-test-secret-" + suffix,
	}
	if ok, err := object.AddApplication(victimApp); err != nil || !ok {
		t.Fatalf("failed to seed victim application: ok=%v err=%v", ok, err)
	}
	defer object.DeleteApplication(victimApp)

	t.Run("GetOrganizationApplications must not disclose another org's applications", func(t *testing.T) {
		c, w := newTestApiController(t, "GET", "/api/get-organization-applications?owner=admin&organization="+victimOrg, sessionUserId)
		c.GetOrganizationApplications()
		resp := decodeControllerResponse(t, w)
		if resp.Status == "ok" {
			t.Fatalf("invariant violated: org-scoped admin of %q read %q's application configuration: %s", ownOrg, victimOrg, w.Body.String())
		}
	})

	// Control: the SAME admin listing their OWN org's applications must
	// keep working - proves the fix denies cross-org access without
	// breaking the legitimate same-org admin path.
	t.Run("control: GetOrganizationApplications still returns the admin's own org", func(t *testing.T) {
		ownApp := &object.Application{
			Owner:        "admin",
			Name:         "own-app-" + suffix,
			Organization: ownOrg,
			DisplayName:  "own app",
			ClientId:     "authz-test-own-client-" + suffix,
			ClientSecret: "authz-test-own-secret-" + suffix,
		}
		if ok, err := object.AddApplication(ownApp); err != nil || !ok {
			t.Fatalf("failed to seed own-org application: ok=%v err=%v", ok, err)
		}
		defer object.DeleteApplication(ownApp)

		c, w := newTestApiController(t, "GET", "/api/get-organization-applications?owner=admin&organization="+ownOrg, sessionUserId)
		c.GetOrganizationApplications()
		resp := decodeControllerResponse(t, w)
		if resp.Status != "ok" {
			t.Fatalf("own-org admin read was unexpectedly denied: %s", w.Body.String())
		}
	})
}
