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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	_ "unsafe"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

//go:linkname testOrmer github.com/casdoor/casdoor/object.ormer
var testOrmer *object.Ormer

//go:linkname testCreateDatabase github.com/casdoor/casdoor/object.createDatabase
var testCreateDatabase bool

func initControllerIsolationTestOrm(t *testing.T) {
	t.Helper()

	if testOrmer != nil {
		return
	}

	dbDir, err := os.MkdirTemp("", "casdoor-controller-security-test-*")
	if err != nil {
		t.Fatalf("failed to create sqlite test dir: %v", err)
	}
	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", dbDir+"/casdoor-controller-security-test.db")
	t.Setenv("dbName", "")

	testCreateDatabase = false
	object.InitAdapter()
	object.CreateTables()
}

func TestAddKeyRejectsCrossOrganizationUserBinding(t *testing.T) {
	initControllerIsolationTestOrm(t)
	seedIsolationUsers(t)

	legitKey := object.Key{
		Owner: "acme", Name: "same_org_key", Type: "User",
		Organization: "acme", User: "alice",
		AccessKey: "AK_SAME_ORG", AccessSecret: "secret", State: "Active",
	}
	controller, recorder := newIsolationController(t, http.MethodPost, "/api/add-key", "acme/acme-admin", legitKey)
	controller.AddKey()
	resp := decodeIsolationResponse(t, recorder)
	if resp.Status != "ok" {
		t.Fatalf("expected same-organization key binding to remain allowed, got status=%q msg=%q", resp.Status, resp.Msg)
	}
	t.Cleanup(func() {
		_, _ = testOrmer.Engine.Delete(&legitKey)
	})

	key := object.Key{
		Owner: "acme", Name: "cross_org_key", Type: "User",
		Organization: "built-in", User: "admin",
		AccessKey: "AK_CROSS_ORG", AccessSecret: "secret", State: "Active",
	}
	controller, recorder = newIsolationController(t, http.MethodPost, "/api/add-key", "acme/acme-admin", key)

	controller.AddKey()

	resp = decodeIsolationResponse(t, recorder)
	if resp.Status != "error" {
		t.Fatalf("expected cross-organization key binding to be rejected, got status=%q data=%v", resp.Status, resp.Data)
	}
}

func TestProviderSecretReadRequiresProviderOwner(t *testing.T) {
	initControllerIsolationTestOrm(t)
	seedIsolationUsers(t)

	provider := &object.Provider{
		Owner: "admin", Name: "foreign-provider", DisplayName: "foreign",
		Category: "Social", Type: "Google", ClientId: "client", ClientSecret: "private-secret",
	}
	if _, err := testOrmer.Engine.Insert(provider); err != nil {
		t.Fatalf("failed to seed provider: %v", err)
	}
	ownProvider := &object.Provider{
		Owner: "acme", Name: "own-provider", DisplayName: "own",
		Category: "Social", Type: "Google", ClientId: "client", ClientSecret: "own-secret",
	}
	if _, err := testOrmer.Engine.Insert(ownProvider); err != nil {
		t.Fatalf("failed to seed own provider: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testOrmer.Engine.Delete(provider)
		_, _ = testOrmer.Engine.Delete(ownProvider)
	})

	controller, recorder := newIsolationController(t, http.MethodGet, "/api/get-provider?id=acme/own-provider&withSecret=1", "acme/acme-admin", nil)
	controller.GetProvider()
	resp := decodeIsolationResponse(t, recorder)
	if resp.Status != "ok" {
		t.Fatalf("expected same-owner provider secret read to remain allowed, got status=%q msg=%q", resp.Status, resp.Msg)
	}

	controller, recorder = newIsolationController(t, http.MethodGet, "/api/get-provider?id=admin/foreign-provider&withSecret=1", "acme/acme-admin", nil)

	controller.GetProvider()

	resp = decodeIsolationResponse(t, recorder)
	if resp.Status != "error" {
		t.Fatalf("expected foreign provider secret read to be rejected, got status=%q data=%v", resp.Status, resp.Data)
	}
}

func TestTransactionReadsRequireSessionOwner(t *testing.T) {
	initControllerIsolationTestOrm(t)
	seedIsolationUsers(t)

	tx := &object.Transaction{
		Owner: "built-in", Name: "foreign-transaction", User: "alice",
		Application: "app-built-in", Domain: "internal.example", Category: object.TransactionCategoryPurchase,
		Provider: "private-provider", Payment: "private-payment", Amount: 42, Currency: "USD",
	}
	if _, err := testOrmer.Engine.Insert(tx); err != nil {
		t.Fatalf("failed to seed transaction: %v", err)
	}
	ownTx := &object.Transaction{
		Owner: "acme", Name: "own-transaction", User: "alice",
		Application: "app-acme", Domain: "acme.example", Category: object.TransactionCategoryPurchase,
		Provider: "acme-provider", Payment: "acme-payment", Amount: 7, Currency: "USD",
	}
	if _, err := testOrmer.Engine.Insert(ownTx); err != nil {
		t.Fatalf("failed to seed own transaction: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testOrmer.Engine.Delete(tx)
		_, _ = testOrmer.Engine.Delete(ownTx)
	})

	controller, recorder := newIsolationController(t, http.MethodGet, "/api/get-transaction?id=acme/own-transaction", "acme/alice", nil)
	controller.GetTransaction()
	resp := decodeIsolationResponse(t, recorder)
	if resp.Status != "ok" {
		t.Fatalf("expected same-tenant transaction detail to remain allowed, got status=%q msg=%q", resp.Status, resp.Msg)
	}

	controller, recorder = newIsolationController(t, http.MethodGet, "/api/get-transactions?owner=acme", "acme/alice", nil)
	controller.GetTransactions()
	resp = decodeIsolationResponse(t, recorder)
	if resp.Status != "ok" {
		t.Fatalf("expected same-tenant transaction list to remain allowed, got status=%q msg=%q", resp.Status, resp.Msg)
	}

	controller, recorder = newIsolationController(t, http.MethodGet, "/api/get-transaction?id=built-in/foreign-transaction", "acme/alice", nil)
	controller.GetTransaction()
	resp = decodeIsolationResponse(t, recorder)
	if resp.Status != "error" {
		t.Fatalf("expected foreign transaction detail to be rejected, got status=%q data=%v", resp.Status, resp.Data)
	}

	controller, recorder = newIsolationController(t, http.MethodGet, "/api/get-transactions?owner=built-in", "acme/alice", nil)
	controller.GetTransactions()
	resp = decodeIsolationResponse(t, recorder)
	if resp.Status != "error" {
		t.Fatalf("expected foreign transaction list to be rejected, got status=%q data=%v", resp.Status, resp.Data)
	}
}

func TestOrderListRequiresSessionOwner(t *testing.T) {
	initControllerIsolationTestOrm(t)
	seedIsolationUsers(t)

	order := &object.Order{
		Owner: "built-in", Name: "foreign-order", User: "alice",
		Payment: "private-payment", Price: 77, Currency: "USD", State: "Paid", Message: "private order",
	}
	if _, err := testOrmer.Engine.Insert(order); err != nil {
		t.Fatalf("failed to seed order: %v", err)
	}
	ownOrder := &object.Order{
		Owner: "acme", Name: "own-order", User: "alice",
		Payment: "acme-payment", Price: 11, Currency: "USD", State: "Paid", Message: "own order",
	}
	if _, err := testOrmer.Engine.Insert(ownOrder); err != nil {
		t.Fatalf("failed to seed own order: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testOrmer.Engine.Delete(order)
		_, _ = testOrmer.Engine.Delete(ownOrder)
	})

	controller, recorder := newIsolationController(t, http.MethodGet, "/api/get-orders?owner=acme", "acme/alice", nil)
	controller.GetOrders()
	resp := decodeIsolationResponse(t, recorder)
	if resp.Status != "ok" {
		t.Fatalf("expected same-tenant order list to remain allowed, got status=%q msg=%q", resp.Status, resp.Msg)
	}

	controller, recorder = newIsolationController(t, http.MethodGet, "/api/get-orders?owner=built-in", "acme/alice", nil)

	controller.GetOrders()

	resp = decodeIsolationResponse(t, recorder)
	if resp.Status != "error" {
		t.Fatalf("expected foreign order list to be rejected, got status=%q data=%v", resp.Status, resp.Data)
	}
}

func seedIsolationUsers(t *testing.T) {
	t.Helper()

	users := []*object.User{
		{Owner: "built-in", Name: "admin", IsAdmin: true},
		{Owner: "acme", Name: "acme-admin", IsAdmin: true},
		{Owner: "acme", Name: "alice", IsAdmin: false},
	}
	for _, user := range users {
		_, _ = testOrmer.Engine.Delete(user)
		if _, err := testOrmer.Engine.Insert(user); err != nil {
			t.Fatalf("failed to seed user %s/%s: %v", user.Owner, user.Name, err)
		}
	}
	t.Cleanup(func() {
		for _, user := range users {
			_, _ = testOrmer.Engine.Delete(user)
		}
	})
}

func newIsolationController(t *testing.T, method string, target string, currentUser string, body interface{}) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()

	var requestBody []byte
	if body != nil {
		var err error
		requestBody, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
	}

	req := httptest.NewRequest(method, target, bytes.NewReader(requestBody))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.RequestBody = requestBody
	ctx.Input.SetData("currentUserId", currentUser)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", controller)
	return controller, recorder
}

func decodeIsolationResponse(t *testing.T, recorder *httptest.ResponseRecorder) *Response {
	t.Helper()

	var resp Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response %q: %v", recorder.Body.String(), err)
	}
	return &resp
}
