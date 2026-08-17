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
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// This file regression-tests TC-0DEC1621: GetOrders() and GetTransactions()
// trusted the caller-supplied `owner` query parameter for non-admin sessions
// instead of deriving it from the session, letting any authenticated user
// list another tenant's orders/transactions for a same-named user. It asserts
// the invariant that a non-admin session can only ever see its own owner's
// records, on both the non-paginated and paginated code paths, while a
// same-tenant (legitimate) request keeps working.

var ownerAuthzDBOnce sync.Once

// setupOwnerAuthzTestDB points the object package's ORM at an isolated MySQL
// database and creates the schema, so this test never touches any seeded
// pentest fixtures. It reuses the same MySQL instance the project's own
// niro/harness/start.sh brings up for local/CI runs (root:123456 on
// 127.0.0.1:${NIRO_MYSQL_PORT:-13306}), but against a private database name.
func setupOwnerAuthzTestDB(t *testing.T) {
	t.Helper()

	port := os.Getenv("NIRO_MYSQL_PORT")
	if port == "" {
		port = "13306"
	}

	if err := os.Setenv("driverName", "mysql"); err != nil {
		t.Fatalf("failed to set driverName env: %v", err)
	}
	if err := os.Setenv("dataSourceName", "root:123456@tcp(127.0.0.1:"+port+")/"); err != nil {
		t.Fatalf("failed to set dataSourceName env: %v", err)
	}
	if err := os.Setenv("dbName", "casdoor_test_tc0dec1621"); err != nil {
		t.Fatalf("failed to set dbName env: %v", err)
	}

	ownerAuthzDBOnce.Do(func() {
		object.InitAdapter()
		object.CreateTables()
	})
}

// newTestApiController builds an ApiController wired to a real (but not yet
// written) HTTP response recorder, bypassing beego routing/session storage.
func newTestApiController(t *testing.T, method, target string) *ApiController {
	t.Helper()

	c := &ApiController{}
	ctx := beegoContext.NewContext()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, nil)
	ctx.Reset(w, req)
	c.Init(ctx, "ApiController", "", nil)
	return c
}

// asNonAdminSession makes GetSessionUsername()/IsAdmin() resolve to the given
// non-admin owner/name pair without needing a real login or session backend:
// GetSessionUsername() checks this context value before touching the session
// store.
func asNonAdminSession(c *ApiController, owner, name string) {
	c.Ctx.Input.SetData("currentUserId", owner+"/"+name)
}

func TestGetOrdersRejectsCrossTenantOwner(t *testing.T) {
	setupOwnerAuthzTestDB(t)

	username := "alice"
	victimOwner := "tc0dec1621-victim-" + util.GenerateId()
	attackerOwner := "tc0dec1621-attacker-" + util.GenerateId()

	victimOrderName := "order-" + util.GenerateId()
	if ok, err := object.AddOrder(&object.Order{
		Owner: victimOwner,
		Name:  victimOrderName,
		User:  username,
		Price: 10,
		State: "Paid",
	}); err != nil || !ok {
		t.Fatalf("failed to seed victim order: ok=%v err=%v", ok, err)
	}

	attackerOrderName := "order-" + util.GenerateId()
	if ok, err := object.AddOrder(&object.Order{
		Owner: attackerOwner,
		Name:  attackerOrderName,
		User:  username,
		Price: 5,
		State: "Created",
	}); err != nil || !ok {
		t.Fatalf("failed to seed attacker's own order: ok=%v err=%v", ok, err)
	}

	// Attack: attackerOwner/alice requests owner=victimOwner.
	attack := newTestApiController(t, http.MethodGet, "/api/get-orders?owner="+victimOwner)
	asNonAdminSession(attack, attackerOwner, username)
	attack.GetOrders()

	attackResp, ok := attack.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %T", attack.Data["json"])
	}
	if attackResp.Status != "ok" {
		t.Fatalf("expected the handler to still return ok status (scoped to caller's own owner), got status=%q msg=%q", attackResp.Status, attackResp.Msg)
	}
	attackOrders, _ := attackResp.Data.([]*object.Order)
	for _, o := range attackOrders {
		if o.Owner == victimOwner {
			t.Fatalf("invariant violated: non-admin session for %s/%s was able to list victim owner %q's order %q via GET /api/get-orders?owner=%s", attackerOwner, username, victimOwner, o.Name, victimOwner)
		}
	}

	// Control: the same attacker session, asking for its own owner, must
	// still see its own order (the fix must not break legitimate access).
	control := newTestApiController(t, http.MethodGet, "/api/get-orders?owner="+attackerOwner)
	asNonAdminSession(control, attackerOwner, username)
	control.GetOrders()

	controlResp, ok := control.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %T", control.Data["json"])
	}
	if controlResp.Status != "ok" {
		t.Fatalf("expected legitimate same-owner request to succeed, got status=%q msg=%q", controlResp.Status, controlResp.Msg)
	}
	controlOrders, _ := controlResp.Data.([]*object.Order)
	found := false
	for _, o := range controlOrders {
		if o.Owner == attackerOwner && o.Name == attackerOrderName {
			found = true
		}
	}
	if !found {
		t.Fatalf("legitimate same-owner request to GET /api/get-orders?owner=%s did not return the caller's own order %q", attackerOwner, attackerOrderName)
	}
}

func TestGetOrdersPaginatedRejectsCrossTenantOwner(t *testing.T) {
	setupOwnerAuthzTestDB(t)

	username := "bob"
	victimOwner := "tc0dec1621-victim-pg-" + util.GenerateId()
	attackerOwner := "tc0dec1621-attacker-pg-" + util.GenerateId()

	victimOrderName := "order-" + util.GenerateId()
	if ok, err := object.AddOrder(&object.Order{
		Owner: victimOwner,
		Name:  victimOrderName,
		User:  username,
		Price: 10,
		State: "Paid",
	}); err != nil || !ok {
		t.Fatalf("failed to seed victim order: ok=%v err=%v", ok, err)
	}

	// Paginated path: pageSize + p present.
	attack := newTestApiController(t, http.MethodGet, "/api/get-orders?owner="+victimOwner+"&pageSize=10&p=1")
	asNonAdminSession(attack, attackerOwner, username)
	attack.GetOrders()

	attackResp, ok := attack.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %T", attack.Data["json"])
	}
	attackOrders, _ := attackResp.Data.([]*object.Order)
	for _, o := range attackOrders {
		if o.Owner == victimOwner {
			t.Fatalf("invariant violated on paginated path: non-admin session for %s/%s was able to list victim owner %q's order %q via GET /api/get-orders?owner=%s&pageSize=10&p=1", attackerOwner, username, victimOwner, o.Name, victimOwner)
		}
	}
}

func TestGetTransactionsRejectsCrossTenantOwner(t *testing.T) {
	setupOwnerAuthzTestDB(t)

	username := "alice"
	victimOwner := "tc0dec1621-tx-victim-" + util.GenerateId()
	attackerOwner := "tc0dec1621-tx-attacker-" + util.GenerateId()

	// Tag is left empty ("") on purpose: object.AddTransaction() only touches
	// balance bookkeeping (which needs seeded organizations/users) when Tag is
	// "Organization" or "User"; otherwise it's a plain insert, which is all
	// this authorization test needs.
	victimOk, _, err := object.AddTransaction(&object.Transaction{
		Owner:  victimOwner,
		User:   username,
		Amount: -10,
		State:  "Created",
	}, "en", false)
	if err != nil || !victimOk {
		t.Fatalf("failed to seed victim transaction: ok=%v err=%v", victimOk, err)
	}

	attackerOk, attackerTxName, err := object.AddTransaction(&object.Transaction{
		Owner:  attackerOwner,
		User:   username,
		Amount: -5,
		State:  "Created",
	}, "en", false)
	if err != nil || !attackerOk {
		t.Fatalf("failed to seed attacker's own transaction: ok=%v err=%v", attackerOk, err)
	}

	// Attack: attackerOwner/alice requests owner=victimOwner.
	attack := newTestApiController(t, http.MethodGet, "/api/get-transactions?owner="+victimOwner)
	asNonAdminSession(attack, attackerOwner, username)
	attack.GetTransactions()

	attackResp, ok := attack.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %T", attack.Data["json"])
	}
	if attackResp.Status != "ok" {
		t.Fatalf("expected the handler to still return ok status (scoped to caller's own owner), got status=%q msg=%q", attackResp.Status, attackResp.Msg)
	}
	attackTxs, _ := attackResp.Data.([]*object.Transaction)
	for _, tx := range attackTxs {
		if tx.Owner == victimOwner {
			t.Fatalf("invariant violated: non-admin session for %s/%s was able to list victim owner %q's transaction %q via GET /api/get-transactions?owner=%s", attackerOwner, username, victimOwner, tx.Name, victimOwner)
		}
	}

	// Control: the same attacker session, asking for its own owner, must
	// still see its own transaction.
	control := newTestApiController(t, http.MethodGet, "/api/get-transactions?owner="+attackerOwner)
	asNonAdminSession(control, attackerOwner, username)
	control.GetTransactions()

	controlResp, ok := control.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %T", control.Data["json"])
	}
	if controlResp.Status != "ok" {
		t.Fatalf("expected legitimate same-owner request to succeed, got status=%q msg=%q", controlResp.Status, controlResp.Msg)
	}
	controlTxs, _ := controlResp.Data.([]*object.Transaction)
	found := false
	for _, tx := range controlTxs {
		if tx.Owner == attackerOwner && tx.Name == attackerTxName {
			found = true
		}
	}
	if !found {
		t.Fatalf("legitimate same-owner request to GET /api/get-transactions?owner=%s did not return the caller's own transaction %q", attackerOwner, attackerTxName)
	}
}
