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
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pp"
	"github.com/casdoor/casdoor/util"
	_ "github.com/go-sql-driver/mysql"
)

// Regression coverage for TC-A898A44D: POST /api/invoice-payment let any
// caller -- including one with no session at all -- fetch and drive the
// invoice workflow for another user's payment by supplying its id, with no
// ownership/admin check. The invariant: invoice generation for a payment
// must require proof that the caller owns the payment (or is an admin),
// mirroring the check the sibling GetPayment handler already performs.

var setupInvoicePaymentDBOnce sync.Once

var invoicePaymentTestDB *sql.DB

var invoicePaymentTestDBName string

func TestMain(m *testing.M) {
	code := m.Run()
	if invoicePaymentTestDB != nil && invoicePaymentTestDBName != "" {
		_, _ = invoicePaymentTestDB.Exec("DROP DATABASE " + invoicePaymentTestDBName)
		_ = invoicePaymentTestDB.Close()
	}
	os.Exit(code)
}

func setupInvoicePaymentDatabase(t *testing.T) {
	t.Helper()

	setupInvoicePaymentDBOnce.Do(func() {
		dbName := fmt.Sprintf("casdoor_invoice_payment_%d", time.Now().UnixNano())
		dsn := "root:123456@tcp(127.0.0.1:13306)/"

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			t.Fatalf("open mysql: %v", err)
		}
		if err := db.Ping(); err != nil {
			t.Fatalf("ping mysql: %v", err)
		}
		if _, err := db.Exec("CREATE DATABASE " + dbName); err != nil {
			t.Fatalf("create test database: %v", err)
		}
		invoicePaymentTestDB = db
		invoicePaymentTestDBName = dbName

		t.Setenv("driverName", "mysql")
		t.Setenv("dataSourceName", dsn)
		t.Setenv("dbName", dbName)
		object.InitConfig()
	})
}

// newInvoicePaymentController builds an ApiController for a single request.
// When sessionUser is empty, currentUserId is set to "" -- exactly what the
// real routers.ApiFilter stashes into the request context for a caller with
// no session at all (see routers/authz_filter.go: subOwner/subName resolve
// to "anonymous"/"anonymous", so username stays ""). Controllers must never
// fall through to Beego's raw session lookup, which panics outside a running
// app/session-middleware context such as this unit test.
func newInvoicePaymentController(t *testing.T, method string, target string, sessionUser string) *ApiController {
	t.Helper()

	request := httptest.NewRequest(method, target, nil)
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, request)
	ctx.Input.SetData("currentUserId", sessionUser)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", controller)
	return controller
}

func invoicePaymentResponse(t *testing.T, controller *ApiController) *Response {
	t.Helper()

	response, ok := controller.Data["json"].(*Response)
	if !ok {
		t.Fatalf("controller response type = %T, want *Response", controller.Data["json"])
	}
	return response
}

func requireInvoicePaymentForbidden(t *testing.T, response *Response) {
	t.Helper()

	if response.Status != "error" || response.Msg != "Forbidden" {
		t.Fatalf("response = status %q msg %q, want Forbidden error", response.Status, response.Msg)
	}
}

func requireInvoicePaymentNotForbidden(t *testing.T, response *Response) {
	t.Helper()

	if response.Status == "error" && response.Msg == "Forbidden" {
		t.Fatalf("response = status %q msg %q, want the request to reach the invoice workflow (any non-Forbidden outcome)", response.Status, response.Msg)
	}
}

func TestInvoicePaymentRejectsAnonymousCaller(t *testing.T) {
	setupInvoicePaymentDatabase(t)

	payment := &object.Payment{
		Owner:       "invoice-owner-org",
		Name:        "alice-payment-anon",
		CreatedTime: util.GetCurrentTime(),
		Provider:    "provider_balance",
		User:        "alice",
		Currency:    "USD",
		Price:       9,
		State:       pp.PaymentStatePaid,
	}
	if _, err := object.AddPayment(payment); err != nil {
		t.Fatalf("add payment: %v", err)
	}

	// No session at all -- a fresh, unauthenticated request, matching the
	// PoC's "no Set-Cookie/Authorization whatsoever" call.
	anon := newInvoicePaymentController(t, http.MethodPost, "/api/invoice-payment?id="+payment.GetId(), "")
	anon.InvoicePayment()
	response := invoicePaymentResponse(t, anon)

	if response.Status != "error" {
		t.Fatalf("anonymous invoice-payment response = status %q msg %q, want an error response -- the request must never reach object.InvoicePayment for a record the caller does not own", response.Status, response.Msg)
	}
	// The anonymous caller must never be treated as if it named alice's
	// specific payment record (which is what the pre-fix vulnerable
	// response echoed back via "failed to update the payment: <name>").
	if strings.Contains(response.Msg, payment.Name) {
		t.Fatalf("anonymous invoice-payment response leaked/acted on the specific payment name: msg %q", response.Msg)
	}
}

func TestInvoicePaymentRejectsNonOwner(t *testing.T) {
	setupInvoicePaymentDatabase(t)

	payment := &object.Payment{
		Owner:       "invoice-owner-org",
		Name:        "alice-payment-cross-user",
		CreatedTime: util.GetCurrentTime(),
		Provider:    "provider_balance",
		User:        "alice",
		Currency:    "USD",
		Price:       9,
		State:       pp.PaymentStatePaid,
	}
	if _, err := object.AddPayment(payment); err != nil {
		t.Fatalf("add payment: %v", err)
	}

	// Authenticated, but as a different, non-admin user in the same
	// organization -- not the payment owner.
	cross := newInvoicePaymentController(t, http.MethodPost, "/api/invoice-payment?id="+payment.GetId(), "invoice-owner-org/bob")
	cross.InvoicePayment()
	requireInvoicePaymentForbidden(t, invoicePaymentResponse(t, cross))
}

func TestInvoicePaymentAllowsOwner(t *testing.T) {
	setupInvoicePaymentDatabase(t)

	payment := &object.Payment{
		Owner:       "invoice-owner-org",
		Name:        "alice-payment-owner",
		CreatedTime: util.GetCurrentTime(),
		Provider:    "provider_balance",
		User:        "alice",
		Currency:    "USD",
		Price:       9,
		State:       pp.PaymentStatePaid,
	}
	if _, err := object.AddPayment(payment); err != nil {
		t.Fatalf("add payment: %v", err)
	}

	// The legitimate owner, authenticated, requesting invoice processing
	// for their own payment must not be blocked by the ownership check.
	owner := newInvoicePaymentController(t, http.MethodPost, "/api/invoice-payment?id="+payment.GetId(), "invoice-owner-org/alice")
	owner.InvoicePayment()
	requireInvoicePaymentNotForbidden(t, invoicePaymentResponse(t, owner))
}
