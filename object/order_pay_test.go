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

package object

import (
	"fmt"
	"sync"
	"testing"

	"github.com/casdoor/casdoor/util"
)

// seedPayOrderRaceFixtures creates an isolated user + product pair (under the
// built-in organization) for exercising PayOrder without touching any other
// test's data, and returns their identifiers.
func seedPayOrderRaceFixtures(t *testing.T, quantity int) (owner, userName, productName string) {
	t.Helper()

	owner = "built-in"
	suffix := util.GenerateId()
	userName = fmt.Sprintf("race-buyer-%s", suffix)
	productName = fmt.Sprintf("race-widget-%s", suffix)

	user := &User{
		Owner:       owner,
		Name:        userName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		Type:        "normal-user",
		DisplayName: "Race Buyer",
		Balance:     1000000,
	}
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	product := &Product{
		Owner:       owner,
		Name:        productName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Race Widget",
		Currency:    "USD",
		Price:       100,
		Quantity:    quantity,
		Sold:        0,
		Providers:   []string{"provider_balance"},
		State:       "Published",
	}
	if _, err := ormer.Engine.Insert(product); err != nil {
		t.Fatalf("failed to seed product: %v", err)
	}

	return owner, userName, productName
}

// seedPayOrderRaceOrder places a single-unit "Created" order for the given
// user/product pair, mirroring what PlaceOrder would produce.
func seedPayOrderRaceOrder(t *testing.T, owner, userName, productName string) *Order {
	t.Helper()

	order := &Order{
		Owner:       owner,
		Name:        fmt.Sprintf("race-order-%s", util.GenerateId()),
		DisplayName: "Race Order",
		CreatedTime: util.GetCurrentTime(),
		Products:    []string{productName},
		ProductInfos: []ProductInfo{{
			Owner:    owner,
			Name:     productName,
			Price:    100,
			Currency: "USD",
			Quantity: 1,
		}},
		User:     userName,
		Price:    100,
		Currency: "USD",
		State:    "Created",
	}
	affected, err := AddOrder(order)
	if err != nil || !affected {
		t.Fatalf("failed to seed order: affected=%v err=%v", affected, err)
	}
	return order
}

// TestPayOrderSingleRequestSucceeds is the legitimate-request control: a
// single pay-order call for a "Created" order must succeed exactly once and
// deduct exactly one unit of stock. If this fails, the harness itself (DB,
// fixtures, balance provider) is broken -- not the concurrency invariant.
func TestPayOrderSingleRequestSucceeds(t *testing.T) {
	InitConfig()
	InitDb()

	owner, userName, productName := seedPayOrderRaceFixtures(t, 50)
	order := seedPayOrderRaceOrder(t, owner, userName, productName)

	o, err := GetOrder(order.GetId())
	if err != nil || o == nil {
		t.Fatalf("failed to fetch order: %v", err)
	}

	_, _, err = PayOrder("provider_balance", "http://localhost:8000", "", o, "en")
	if err != nil {
		t.Fatalf("expected a single pay-order request to succeed, got error: %v", err)
	}

	finalOrder, err := GetOrder(order.GetId())
	if err != nil || finalOrder == nil {
		t.Fatalf("failed to reload order: %v", err)
	}
	if finalOrder.State != "Paid" {
		t.Errorf("expected order state to be Paid, got %q", finalOrder.State)
	}

	finalProduct, err := GetProduct(fmt.Sprintf("%s/%s", owner, productName))
	if err != nil || finalProduct == nil {
		t.Fatalf("failed to reload product: %v", err)
	}
	if finalProduct.Quantity != 49 || finalProduct.Sold != 1 {
		t.Errorf("expected stock to move by exactly 1 unit (quantity 49, sold 1), got quantity=%d sold=%d", finalProduct.Quantity, finalProduct.Sold)
	}
}

// TestPayOrderConcurrentRequestsPayOnce is the regression test for
// TC-A0DBFF35: paying for one order must only ever be able to succeed once.
// Firing several concurrent pay-order requests for the same "Created" order
// must let exactly one succeed, create exactly one Payment record, and
// deduct stock exactly once -- never once per concurrent request.
func TestPayOrderConcurrentRequestsPayOnce(t *testing.T) {
	InitConfig()
	InitDb()

	owner, userName, productName := seedPayOrderRaceFixtures(t, 50)
	order := seedPayOrderRaceOrder(t, owner, userName, productName)

	const concurrency = 8
	var wg sync.WaitGroup
	results := make([]error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Mirror controllers/order_pay.go: every concurrent HTTP request
			// fetches its own, independently-read copy of the order before
			// calling PayOrder.
			o, err := GetOrder(order.GetId())
			if err != nil || o == nil {
				results[i] = fmt.Errorf("failed to fetch order: %v", err)
				return
			}
			_, _, err = PayOrder("provider_balance", "http://localhost:8000", "", o, "en")
			results[i] = err
		}(i)
	}
	wg.Wait()

	successCount := 0
	for _, err := range results {
		if err == nil {
			successCount++
		}
	}
	if successCount != 1 {
		t.Errorf("invariant violated: expected exactly 1 successful pay-order out of %d concurrent requests for one order, got %d", concurrency, successCount)
	}

	payments, err := GetUserPayments(owner, userName)
	if err != nil {
		t.Fatalf("failed to fetch payments: %v", err)
	}
	paymentCount := 0
	for _, p := range payments {
		if p.Order == order.Name {
			paymentCount++
		}
	}
	if paymentCount != 1 {
		t.Errorf("invariant violated: expected exactly 1 Payment record for order %s, got %d", order.Name, paymentCount)
	}

	finalOrder, err := GetOrder(order.GetId())
	if err != nil || finalOrder == nil {
		t.Fatalf("failed to reload order: %v", err)
	}
	if finalOrder.State != "Paid" {
		t.Errorf("expected order to end up Paid exactly once, got state %q", finalOrder.State)
	}

	finalProduct, err := GetProduct(fmt.Sprintf("%s/%s", owner, productName))
	if err != nil || finalProduct == nil {
		t.Fatalf("failed to reload product: %v", err)
	}
	if finalProduct.Quantity != 49 || finalProduct.Sold != 1 {
		t.Errorf("invariant violated: expected stock to move by exactly 1 unit for a 1-unit order regardless of concurrent pay attempts, got quantity=%d sold=%d", finalProduct.Quantity, finalProduct.Sold)
	}
}
