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

// Regression tests for TC-F4D16A39 and TC-BBF6EB61: both /api/invoice-payment
// and /api/get-subscription are reachable via a Casbin policy that allows any
// caller (including anonymous ones), same as the sibling endpoints
// /api/pay-order, /api/cancel-order, /api/get-order and /api/get-payment.
// Those siblings self-defend with an in-handler ownership check; before this
// fix, InvoicePayment and GetSubscription had none.
//
// These tests exercise the controller methods directly (bypassing the HTTP
// session/cookie machinery, which is not the code under test) by building a
// beego context whose "currentUserId" data mirrors exactly what
// routers.ApiFilter injects for an authenticated caller, and by leaving it
// unset to represent a fully anonymous caller.

import (
	gocontext "context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/beego/beego/v2/server/web/session"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pp"
	"github.com/casdoor/casdoor/util"
)

var initOwnershipTestDbOnce sync.Once

// initOwnershipTestDb connects to the same database the rest of the "go
// test ./..." suite uses (conf/app.conf), exactly like the existing
// object.InitConfig()-based tests (e.g. object/transaction_test.go).
func initOwnershipTestDb() {
	initOwnershipTestDbOnce.Do(func() {
		object.InitConfig()
	})
}

// fakeSessionStore is a minimal in-memory session.Store so GetSessionUsername
// / GetSession can run without a real cookie-backed session provider. It is
// never populated with "username" for these tests: authenticated callers are
// represented the same way routers.ApiFilter represents them to the
// controller layer, via the "currentUserId" context datum consumed first by
// GetSessionUsername.
type fakeSessionStore struct {
	mu   sync.Mutex
	data map[interface{}]interface{}
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{data: map[interface{}]interface{}{}}
}

func (s *fakeSessionStore) Set(_ gocontext.Context, key, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

func (s *fakeSessionStore) Get(_ gocontext.Context, key interface{}) interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[key]
}

func (s *fakeSessionStore) Delete(_ gocontext.Context, key interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *fakeSessionStore) SessionID(_ gocontext.Context) string { return "test-session" }

func (s *fakeSessionStore) SessionReleaseIfPresent(_ gocontext.Context, _ http.ResponseWriter) {}

func (s *fakeSessionStore) SessionRelease(_ gocontext.Context, _ http.ResponseWriter) {}

func (s *fakeSessionStore) Flush(_ gocontext.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[interface{}]interface{}{}
	return nil
}

var _ session.Store = (*fakeSessionStore)(nil)

type testResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

// newOwnershipTestController builds an *ApiController wired to an
// httptest.ResponseRecorder, exactly as beego would for a live request, with
// sessionUsername (an "owner/name" id, matching what ApiFilter injects for a
// logged-in user) set as the caller's identity. An empty sessionUsername
// represents a fully anonymous caller, matching the PoC's un-cookied request.
func newOwnershipTestController(method, target, sessionUsername string) (*ApiController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(rec, req)
	ctx.Input.CruSession = newFakeSessionStore()
	if sessionUsername != "" {
		ctx.Input.SetData("currentUserId", sessionUsername)
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "", nil)
	return c, rec
}

func decodeTestResponse(t *testing.T, rec *httptest.ResponseRecorder) *testResponse {
	t.Helper()
	var resp testResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v, body=%s", err, rec.Body.String())
	}
	return &resp
}

// --- TC-F4D16A39: POST /api/invoice-payment ---

func addOwnershipTestPayment(t *testing.T, owner, name, user, providerName string) *object.Payment {
	t.Helper()

	provider := &object.Provider{
		Owner:       owner,
		Name:        providerName,
		DisplayName: providerName,
		Category:    "Payment",
		Type:        "Dummy",
	}
	if _, err := object.AddProvider(provider); err != nil {
		t.Fatalf("failed to seed test payment provider: %v", err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteProvider(provider)
	})

	payment := &object.Payment{
		Owner:    owner,
		Name:     name,
		Provider: providerName,
		Type:     "Payment",
		User:     user,
		State:    pp.PaymentStatePaid,
		// Seeded non-empty so that the Dummy provider's GetInvoice() (which
		// always returns "") produces a genuine, detectable column change on
		// UpdatePayment's AllCols().Update - otherwise MySQL reports 0 rows
		// affected for a no-op write and object.InvoicePayment returns an
		// unrelated "failed to update the payment" error that would mask the
		// authorization check under test.
		InvoiceUrl: "https://example.com/pending-invoice",
	}
	if _, err := object.AddPayment(payment); err != nil {
		t.Fatalf("failed to seed test payment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = object.DeletePayment(payment)
	})

	return payment
}

// TestInvoicePaymentRejectsNonOwner is the regression test for TC-F4D16A39:
// an authenticated user who does not own the payment must be rejected with
// an authorization error, not "ok", matching the sibling /api/pay-order and
// /api/cancel-order handlers.
func TestInvoicePaymentRejectsNonOwner(t *testing.T) {
	initOwnershipTestDb()

	owner := "authz-test-org-f4d16a39"
	payment := addOwnershipTestPayment(t, owner, "payment-nonowner", "payment-owner-user", "provider-nonowner")

	c, rec := newOwnershipTestController(http.MethodPost, "/api/invoice-payment?id="+payment.GetId(), util.GetId(owner, "unrelated-user"))
	c.InvoicePayment()

	resp := decodeTestResponse(t, rec)
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: a non-owner was allowed to invoke invoice-payment on another user's payment; response=%+v", resp)
	}
	if resp.Msg != "Unauthorized operation" {
		t.Fatalf("expected the same %q error the sibling pay-order/cancel-order handlers return, got status=%q msg=%q", "Unauthorized operation", resp.Status, resp.Msg)
	}
}

// TestInvoicePaymentRejectsAnonymous is the regression test for TC-F4D16A39:
// a fully unauthenticated caller (no session at all) must be rejected the
// same way.
func TestInvoicePaymentRejectsAnonymous(t *testing.T) {
	initOwnershipTestDb()

	owner := "authz-test-org-f4d16a39"
	payment := addOwnershipTestPayment(t, owner, "payment-anon", "payment-owner-user", "provider-anon")

	c, rec := newOwnershipTestController(http.MethodPost, "/api/invoice-payment?id="+payment.GetId(), "")
	c.InvoicePayment()

	resp := decodeTestResponse(t, rec)
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: an anonymous caller was allowed to invoke invoice-payment on another user's payment; response=%+v", resp)
	}
	if resp.Msg != "Unauthorized operation" {
		t.Fatalf("expected %q, got status=%q msg=%q", "Unauthorized operation", resp.Status, resp.Msg)
	}
}

// TestInvoicePaymentAllowsOwner is the positive control: the payment's own
// owner must still be able to invoke invoice-payment successfully. Without
// this, a passing "rejects non-owner" test would be meaningless (it could
// just be rejecting everyone).
func TestInvoicePaymentAllowsOwner(t *testing.T) {
	initOwnershipTestDb()

	owner := "authz-test-org-f4d16a39"
	user := "payment-owner-user"
	payment := addOwnershipTestPayment(t, owner, "payment-owner-ok", user, "provider-owner-ok")

	c, rec := newOwnershipTestController(http.MethodPost, "/api/invoice-payment?id="+payment.GetId(), util.GetId(owner, user))
	c.InvoicePayment()

	resp := decodeTestResponse(t, rec)
	if resp.Status != "ok" {
		t.Fatalf("positive control failed: the payment owner was rejected by invoice-payment (status=%q msg=%q) - environment may be broken, the red/green result above cannot be trusted", resp.Status, resp.Msg)
	}
}

// --- TC-BBF6EB61: GET /api/get-subscription ---

func addOwnershipTestSubscription(t *testing.T, owner, name, user string) *object.Subscription {
	t.Helper()

	subscription := &object.Subscription{
		Owner: owner,
		Name:  name,
		User:  user,
		State: object.SubStateActive,
	}
	if _, err := object.AddSubscription(subscription); err != nil {
		t.Fatalf("failed to seed test subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteSubscription(subscription)
	})

	return subscription
}

// TestGetSubscriptionRejectsNonOwner is the regression test for
// TC-BBF6EB61: an authenticated user who does not own the subscription must
// be rejected with "Forbidden", not handed the record, matching the sibling
// /api/get-order and /api/get-payment handlers.
func TestGetSubscriptionRejectsNonOwner(t *testing.T) {
	initOwnershipTestDb()

	owner := "authz-test-org-bbf6eb61"
	sub := addOwnershipTestSubscription(t, owner, "sub-nonowner", "sub-owner-user")

	c, rec := newOwnershipTestController(http.MethodGet, "/api/get-subscription?id="+util.GetId(sub.Owner, sub.Name), util.GetId(owner, "unrelated-user"))
	c.GetSubscription()

	resp := decodeTestResponse(t, rec)
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: a non-owner was able to read another user's subscription record: %s", string(resp.Data))
	}
	if resp.Msg != "Forbidden" {
		t.Fatalf("expected the same %q error the sibling get-order/get-payment handlers return, got status=%q msg=%q", "Forbidden", resp.Status, resp.Msg)
	}
}

// TestGetSubscriptionRejectsAnonymous is the regression test for
// TC-BBF6EB61: a fully unauthenticated caller must not receive the record.
func TestGetSubscriptionRejectsAnonymous(t *testing.T) {
	initOwnershipTestDb()

	owner := "authz-test-org-bbf6eb61"
	sub := addOwnershipTestSubscription(t, owner, "sub-anon", "sub-owner-user")

	c, rec := newOwnershipTestController(http.MethodGet, "/api/get-subscription?id="+util.GetId(sub.Owner, sub.Name), "")
	c.GetSubscription()

	resp := decodeTestResponse(t, rec)
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: an anonymous caller was able to read another user's subscription record: %s", string(resp.Data))
	}
}

// TestGetSubscriptionAllowsOwner is the positive control: the subscription's
// own owner must still be able to read it.
func TestGetSubscriptionAllowsOwner(t *testing.T) {
	initOwnershipTestDb()

	owner := "authz-test-org-bbf6eb61"
	user := "sub-owner-user"
	sub := addOwnershipTestSubscription(t, owner, "sub-owner-ok", user)

	c, rec := newOwnershipTestController(http.MethodGet, "/api/get-subscription?id="+util.GetId(sub.Owner, sub.Name), util.GetId(owner, user))
	c.GetSubscription()

	resp := decodeTestResponse(t, rec)
	if resp.Status != "ok" {
		t.Fatalf("positive control failed: the subscription owner was rejected by get-subscription (status=%q msg=%q) - environment may be broken, the red/green result above cannot be trusted", resp.Status, resp.Msg)
	}
	var got object.Subscription
	if err := json.Unmarshal(resp.Data, &got); err != nil {
		t.Fatalf("failed to parse subscription data: %v", err)
	}
	if got.Owner != owner || got.Name != sub.Name {
		t.Fatalf("owner got back the wrong subscription: %+v", got)
	}
}
