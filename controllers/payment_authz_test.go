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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pp"
	"github.com/casdoor/casdoor/util"
)

// callInvoicePayment drives (*ApiController).InvoicePayment() in-process,
// the same way a live HTTP request does, but without a real socket or
// session cookie: GetSessionUsername() reads
// ctx.Input.GetData("currentUserId") first, which is exactly what
// routers.ApiFilter (see routers/authz_filter.go ApiFilter) stashes there
// for every real request - including anonymous ones, for which it stashes
// the empty string rather than leaving the key unset. Setting it directly
// here (always, even to "") exercises the real, unmodified controller
// method end to end. An empty signedInUserId simulates a fully
// unauthenticated caller: no cookie set at all, matching the PoC's bare
// http.Client with no jar.
func callInvoicePayment(t *testing.T, signedInUserId, paymentId string) (status string, msg string, body []byte) {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, "/api/invoice-payment?id="+paymentId, nil)
	w := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(w, r)
	ctx.Input.SetData("currentUserId", signedInUserId)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "InvoicePayment", nil)
	c.InvoicePayment()

	body = w.Body.Bytes()
	var parsed Response
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("InvoicePayment did not return valid JSON: %v (body=%s)", err, body)
	}
	return parsed.Status, parsed.Msg, body
}

// TestInvoicePaymentEnforcesCallerOwnership is a regression test for
// TC-72A9813C: InvoicePayment() called object.GetPayment(id) then
// object.InvoicePayment(payment) with no session/ownership check at all,
// unlike the adjacent GetPayment handler in this same file. That let a
// fully unauthenticated caller (no cookie, no auth header) force invoice
// (re)generation - which unconditionally writes payment.InvoiceUrl via a
// full-record UpdatePayment() - for any payment record just by knowing or
// guessing its owner/name identifier.
//
// Fixtures are created directly through the object package (this
// package's own test factories), not read from Niro's ephemeral harness
// seed data, so this test is self-contained and reproducible against any
// freshly booted instance. It relies on the "admin/provider_payment_dummy"
// Payment provider seeded by object.InitDb() at application startup (the
// live process backing this test suite's database already ran that seed).
func TestInvoicePaymentEnforcesCallerOwnership(t *testing.T) {
	object.InitConfig()
	object.InitUserManager()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	testOrg := "niro-regress-org-" + suffix
	testApp := "niro-regress-app-" + suffix
	payingUserName := "niro-regress-payer-" + suffix
	otherUserName := "niro-regress-other-" + suffix
	paymentName := "niro-regress-payment-" + suffix

	organization := &object.Organization{
		Owner:       "admin",
		Name:        testOrg,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: testOrg,
	}
	if _, err := object.AddOrganization(organization); err != nil {
		t.Fatalf("harness problem: could not create test organization: %v", err)
	}
	defer object.DeleteOrganization(organization)

	application := &object.Application{
		Owner:        "admin",
		Name:         testApp,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  testApp,
		Organization: testOrg,
	}
	if _, err := object.AddApplication(application); err != nil {
		t.Fatalf("harness problem: could not create test application: %v", err)
	}
	defer object.DeleteApplication(application)

	payingUser := &object.User{
		Owner:       testOrg,
		Name:        payingUserName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     false,
	}
	if _, err := object.AddUser(payingUser, "en"); err != nil {
		t.Fatalf("harness problem: could not create paying test user: %v", err)
	}
	defer object.DeleteUser(payingUser)

	otherUser := &object.User{
		Owner:       testOrg,
		Name:        otherUserName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     false,
	}
	if _, err := object.AddUser(otherUser, "en"); err != nil {
		t.Fatalf("harness problem: could not create other test user: %v", err)
	}
	defer object.DeleteUser(otherUser)

	// Each subtest gets its own freshly-created Paid payment, seeded with a
	// non-empty, stale InvoiceUrl. That guarantees a *legitimate* successful
	// call (own user / admin) actually changes the stored row when the dummy
	// provider overwrites it with "" - i.e. it exercises exactly the
	// "overwrite the stored invoice URL" behavior described in the finding,
	// rather than tripping the unrelated no-op-update edge case (repeatedly
	// writing back the same empty value would report zero rows affected).
	newPaymentId := func(t *testing.T, label string) string {
		t.Helper()
		name := paymentName + "-" + label
		payment := &object.Payment{
			Owner:              testOrg,
			Name:               name,
			CreatedTime:        util.GetCurrentTime(),
			DisplayName:        name,
			Provider:           "provider_payment_dummy",
			Type:               "PayPal",
			ProductName:        "niro-regress-product",
			ProductDisplayName: "niro-regress-product",
			Detail:             "niro-regress TC-72A9813C",
			Currency:           "USD",
			Price:              10,
			User:               payingUserName,
			PersonName:         "Niro Regress",
			PersonEmail:        "niro-regress@example.com",
			State:              pp.PaymentStatePaid,
			InvoiceUrl:         "https://old-invoice.example.com/stale-" + label,
		}
		if _, err := object.AddPayment(payment); err != nil {
			t.Fatalf("harness problem: could not create Paid test payment: %v", err)
		}
		t.Cleanup(func() { object.DeletePayment(payment) })
		return payment.GetId()
	}

	t.Run("anonymous caller cannot trigger invoice generation", func(t *testing.T) {
		paymentId := newPaymentId(t, "anon")
		status, msg, body := callInvoicePayment(t, "", paymentId)
		if status == "ok" {
			t.Fatalf("invariant violated: a fully unauthenticated caller (no session) triggered invoice generation on %s - unauthorized state mutation. body=%s", paymentId, body)
		}
		t.Logf("denied as expected: status=%s msg=%s", status, msg)
	})

	t.Run("a different authenticated user in the same org cannot trigger invoice generation on someone else's payment", func(t *testing.T) {
		paymentId := newPaymentId(t, "cross-user")
		status, msg, body := callInvoicePayment(t, testOrg+"/"+otherUserName, paymentId)
		if status == "ok" {
			t.Fatalf("invariant violated: user %s/%s triggered invoice generation on %s/%s's payment - cross-user unauthorized write. body=%s", testOrg, otherUserName, testOrg, payingUserName, body)
		}
		t.Logf("denied as expected: status=%s msg=%s", status, msg)
	})

	t.Run("control: the payment's own user can trigger invoice generation", func(t *testing.T) {
		paymentId := newPaymentId(t, "own-user")
		status, msg, body := callInvoicePayment(t, testOrg+"/"+payingUserName, paymentId)
		if status != "ok" {
			t.Fatalf("harness problem: the payment's own user %s/%s could not trigger invoice generation on their own record (status=%s msg=%s) - the fix over-restricted legitimate access. body=%s", testOrg, payingUserName, status, msg, body)
		}
	})

	t.Run("control: global admin can trigger invoice generation on any record", func(t *testing.T) {
		paymentId := newPaymentId(t, "global-admin")
		status, msg, body := callInvoicePayment(t, "built-in/admin", paymentId)
		if status != "ok" {
			t.Fatalf("harness problem: global admin (built-in/admin) could not trigger invoice generation on %s (status=%s msg=%s) - the fix over-restricted legitimate global-admin access. body=%s", paymentId, status, msg, body)
		}
	})
}
