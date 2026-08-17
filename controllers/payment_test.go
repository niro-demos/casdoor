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
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	beegoCtx "github.com/beego/beego/v2/server/web/context"
	"github.com/beego/beego/v2/server/web/session"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pp"
)

// testSessionManager is a minimal in-memory beego session manager, good
// enough to give each simulated request a real (but empty) session store so
// that ApiController.GetSession*() never dereferences a nil CruSession -
// exactly what beego's own router wires up per-request in production.
var testSessionManager *session.Manager

func getTestSessionManager(t *testing.T) *session.Manager {
	t.Helper()
	if testSessionManager != nil {
		return testSessionManager
	}
	mgr, err := session.NewManager("memory", &session.ManagerConfig{
		CookieName:  "casdoor_test_session_id",
		Gclifetime:  3600,
		Maxlifetime: 3600,
	})
	if err != nil {
		t.Fatalf("failed to create test session manager: %v", err)
	}
	testSessionManager = mgr
	return mgr
}

// newTestApiController builds a real *ApiController wired to a real beego
// context.Context (request/response recorder pair), the same type the app
// uses in production. When currentUserId is non-empty it is injected into
// the beego context data under "currentUserId" - exactly how casdoor's own
// ApiFilter stores the authenticated caller's id after verifying their
// session/JWT (see ApiController.GetSessionUsername, controllers/base.go).
// An empty currentUserId simulates a caller with no session at all.
func newTestApiController(t *testing.T, method, target, currentUserId string) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()

	ctx := beegoCtx.NewContext()
	ctx.Reset(w, req)

	cruSession, err := getTestSessionManager(t).SessionStart(w, req)
	if err != nil {
		t.Fatalf("failed to start test session: %v", err)
	}
	ctx.Input.CruSession = cruSession

	if currentUserId != "" {
		ctx.Input.SetData("currentUserId", currentUserId)
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "", nil)
	return c, w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) *Response {
	t.Helper()
	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode controller response %q: %v", w.Body.String(), err)
	}
	return &resp
}

// setUpInvoicePaymentFixture creates a fresh, isolated Paid payment (owned
// by ownerOwner/ownerUser) backed by the dummy payment provider, mirroring
// the fixture the TC-32A02631 PoC builds via /api/buy-product +
// /api/notify-payment. Returns the payment id ("owner/name") and a cleanup
// func.
func setUpInvoicePaymentFixture(t *testing.T, ownerOwner, ownerUser string) (string, func()) {
	t.Helper()

	object.InitConfig()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	providerName := "provider_test_dummy_" + suffix
	paymentName := "payment_test_" + suffix

	provider := &object.Provider{
		Owner: ownerOwner,
		Name:  providerName,
		Type:  "Dummy",
	}
	if ok, err := object.AddProvider(provider); err != nil || !ok {
		t.Fatalf("failed to create test payment provider: ok=%v err=%v", ok, err)
	}

	payment := &object.Payment{
		Owner:    ownerOwner,
		Name:     paymentName,
		Provider: providerName,
		Type:     "Dummy",
		User:     ownerUser,
		State:    pp.PaymentStatePaid,
	}
	if ok, err := object.AddPayment(payment); err != nil || !ok {
		t.Fatalf("failed to create test payment: ok=%v err=%v", ok, err)
	}

	paymentId := ownerOwner + "/" + paymentName

	cleanup := func() {
		_, _ = object.DeletePayment(payment)
		_, _ = object.DeleteProvider(provider)
	}

	return paymentId, cleanup
}

// TestInvoicePaymentEnforcesOwnership is the regression test for
// TC-32A02631: POST /api/invoice-payment must enforce the same
// owner/user check that GET /api/get-payment already enforces for the
// identical `id` parameter. An authenticated-but-unrelated caller, and a
// caller with no session at all, must both be rejected with "Forbidden"
// before the request ever reaches the business logic that talks to the
// payment provider. The rightful owner must not be rejected.
func TestInvoicePaymentEnforcesOwnership(t *testing.T) {
	const ownerOwner = "invoice-payment-test-org"
	const ownerUser = "owner"
	const attackerOwner = "invoice-payment-test-org-attacker"
	const attackerUser = "attacker"

	paymentId, cleanup := setUpInvoicePaymentFixture(t, ownerOwner, ownerUser)
	defer cleanup()

	target := "/api/invoice-payment?id=" + paymentId

	t.Run("cross-tenant authenticated caller is rejected", func(t *testing.T) {
		c, w := newTestApiController(t, "POST", target, attackerOwner+"/"+attackerUser)
		c.InvoicePayment()

		resp := decodeResponse(t, w)
		if resp.Status != "error" || resp.Msg != "Forbidden" {
			t.Fatalf("expected an unrelated authenticated user to be rejected with Forbidden, got status=%q msg=%q (body=%s)", resp.Status, resp.Msg, w.Body.String())
		}
	})

	t.Run("unauthenticated caller is rejected", func(t *testing.T) {
		c, w := newTestApiController(t, "POST", target, "")
		c.InvoicePayment()

		resp := decodeResponse(t, w)
		if resp.Status != "error" || resp.Msg != "Forbidden" {
			t.Fatalf("expected a caller with no session to be rejected with Forbidden, got status=%q msg=%q (body=%s)", resp.Status, resp.Msg, w.Body.String())
		}
	})

	t.Run("rightful owner is not rejected by the ownership check", func(t *testing.T) {
		c, w := newTestApiController(t, "POST", target, ownerOwner+"/"+ownerUser)
		c.InvoicePayment()

		resp := decodeResponse(t, w)
		if resp.Status == "error" && resp.Msg == "Forbidden" {
			t.Fatalf("expected the rightful owner to pass the ownership check (any downstream provider outcome is fine), got status=%q msg=%q (body=%s)", resp.Status, resp.Msg, w.Body.String())
		}
	})
}
