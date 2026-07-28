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

var setupOwnerBindingDatabaseOnce sync.Once
var ownerBindingTestDB *sql.DB
var ownerBindingTestDBName string

func TestMain(m *testing.M) {
	code := m.Run()
	if ownerBindingTestDB != nil && ownerBindingTestDBName != "" {
		_, _ = ownerBindingTestDB.Exec("DROP DATABASE " + ownerBindingTestDBName)
		_ = ownerBindingTestDB.Close()
	}
	os.Exit(code)
}

func setupOwnerBindingDatabase(t *testing.T) {
	t.Helper()

	setupOwnerBindingDatabaseOnce.Do(func() {
		dbName := fmt.Sprintf("casdoor_owner_binding_%d", time.Now().UnixNano())
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
		ownerBindingTestDB = db
		ownerBindingTestDBName = dbName

		t.Setenv("driverName", "mysql")
		t.Setenv("dataSourceName", dsn)
		t.Setenv("dbName", dbName)
		object.InitConfig()
	})
}

func newOwnerBindingController(t *testing.T, method string, target string, sessionUser string) *ApiController {
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

func responseFromController(t *testing.T, controller *ApiController) *Response {
	t.Helper()

	response, ok := controller.Data["json"].(*Response)
	if !ok {
		t.Fatalf("controller response type = %T, want *Response", controller.Data["json"])
	}
	return response
}

func requireStatus(t *testing.T, response *Response, status string) {
	t.Helper()

	if response.Status != status {
		t.Fatalf("response status = %q msg = %q, want %q", response.Status, response.Msg, status)
	}
}

func requireForbidden(t *testing.T, response *Response) {
	t.Helper()

	if response.Status != "error" || response.Msg != "Forbidden" {
		t.Fatalf("response = status %q msg %q, want Forbidden error", response.Status, response.Msg)
	}
}

func requireOrderOwners(t *testing.T, data interface{}, owner string) {
	t.Helper()

	orders, ok := data.([]*object.Order)
	if !ok {
		t.Fatalf("response data type = %T, want []*object.Order", data)
	}
	if len(orders) == 0 {
		t.Fatalf("expected at least one order for owner %q", owner)
	}
	for _, order := range orders {
		if order.Owner != owner {
			t.Fatalf("returned order owner = %q, want %q", order.Owner, owner)
		}
	}
}

func requireTransactionOwners(t *testing.T, data interface{}, owner string) {
	t.Helper()

	transactions, ok := data.([]*object.Transaction)
	if !ok {
		t.Fatalf("response data type = %T, want []*object.Transaction", data)
	}
	if len(transactions) == 0 {
		t.Fatalf("expected at least one transaction for owner %q", owner)
	}
	for _, transaction := range transactions {
		if transaction.Owner != owner {
			t.Fatalf("returned transaction owner = %q, want %q", transaction.Owner, owner)
		}
	}
}

func TestGetOrdersRequiresSessionOwnerForSelfAccess(t *testing.T) {
	setupOwnerBindingDatabase(t)

	alphaOrder := &object.Order{
		Owner:       "owner-binding-alpha",
		Name:        "alpha-order",
		CreatedTime: util.GetCurrentTime(),
		User:        "alice",
		Price:       9,
		Currency:    "USD",
		State:       "Created",
	}
	betaOrder := &object.Order{
		Owner:       "owner-binding-beta",
		Name:        "beta-order",
		CreatedTime: util.GetCurrentTime(),
		User:        "alice",
		Price:       11,
		Currency:    "USD",
		State:       "Created",
	}
	for _, order := range []*object.Order{alphaOrder, betaOrder} {
		if _, err := object.AddOrder(order); err != nil {
			t.Fatalf("add order %s: %v", order.GetId(), err)
		}
	}

	own := newOwnerBindingController(t, http.MethodGet, "/api/get-orders?owner=owner-binding-beta", "owner-binding-beta/alice")
	own.GetOrders()
	ownResponse := responseFromController(t, own)
	requireStatus(t, ownResponse, "ok")
	requireOrderOwners(t, ownResponse.Data, "owner-binding-beta")

	cross := newOwnerBindingController(t, http.MethodGet, "/api/get-orders?owner=owner-binding-alpha", "owner-binding-beta/alice")
	cross.GetOrders()
	requireForbidden(t, responseFromController(t, cross))
}

func TestGetTransactionsRequiresSessionOwnerForSelfAccess(t *testing.T) {
	setupOwnerBindingDatabase(t)

	alphaTransaction := &object.Transaction{
		Owner:       "owner-binding-alpha",
		CreatedTime: util.GetCurrentTime(),
		User:        "alice",
		Application: "app-owner-binding-alpha",
		Category:    object.TransactionCategoryPurchase,
		Type:        "Scout",
		Currency:    "USD",
		State:       "Created",
	}
	betaTransaction := &object.Transaction{
		Owner:       "owner-binding-beta",
		CreatedTime: util.GetCurrentTime(),
		User:        "alice",
		Application: "app-owner-binding-beta",
		Category:    object.TransactionCategoryPurchase,
		Type:        "Scout",
		Currency:    "USD",
		State:       "Created",
	}
	for _, transaction := range []*object.Transaction{alphaTransaction, betaTransaction} {
		if _, err := object.AddExternalPaymentTransaction(transaction, "en"); err != nil {
			t.Fatalf("add transaction for %s/%s: %v", transaction.Owner, transaction.User, err)
		}
	}

	own := newOwnerBindingController(t, http.MethodGet, "/api/get-transactions?owner=owner-binding-beta", "owner-binding-beta/alice")
	own.GetTransactions()
	ownResponse := responseFromController(t, own)
	requireStatus(t, ownResponse, "ok")
	requireTransactionOwners(t, ownResponse.Data, "owner-binding-beta")

	crossList := newOwnerBindingController(t, http.MethodGet, "/api/get-transactions?owner=owner-binding-alpha", "owner-binding-beta/alice")
	crossList.GetTransactions()
	requireForbidden(t, responseFromController(t, crossList))

	crossSingle := newOwnerBindingController(t, http.MethodGet, "/api/get-transaction?id="+alphaTransaction.GetId(), "owner-binding-beta/alice")
	crossSingle.GetTransaction()
	singleResponse := responseFromController(t, crossSingle)
	if singleResponse.Status != "error" {
		t.Fatalf("single transaction response status = %q, want error", singleResponse.Status)
	}
}

func TestInvoicePaymentRequiresPaymentOwnerForSelfAccess(t *testing.T) {
	setupOwnerBindingDatabase(t)

	payment := &object.Payment{
		Owner:       "owner-binding-alpha",
		Name:        "bob-payment",
		CreatedTime: util.GetCurrentTime(),
		Provider:    "missing-provider",
		User:        "bob",
		Currency:    "USD",
		Price:       9,
		State:       pp.PaymentStateCreated,
	}
	if _, err := object.AddPayment(payment); err != nil {
		t.Fatalf("add payment: %v", err)
	}

	owner := newOwnerBindingController(t, http.MethodPost, "/api/invoice-payment?id="+payment.GetId(), "owner-binding-alpha/bob")
	owner.InvoicePayment()
	ownerResponse := responseFromController(t, owner)
	if ownerResponse.Status == "error" && strings.Contains(ownerResponse.Msg, "Forbidden") {
		t.Fatalf("owner invoice response = status %q msg %q, want non-Forbidden invoice workflow response", ownerResponse.Status, ownerResponse.Msg)
	}

	cross := newOwnerBindingController(t, http.MethodPost, "/api/invoice-payment?id="+payment.GetId(), "owner-binding-alpha/alice")
	cross.InvoicePayment()
	requireForbidden(t, responseFromController(t, cross))
}
