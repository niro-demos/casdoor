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
	"testing"
	"time"

	"github.com/casdoor/casdoor/util"
)

// setupOrderPayTestFixtures creates a fully isolated org/provider/product/user
// so this test never touches shared fixtures. It mirrors the scenario in
// TC-D61BA51E: a standard buyer, an internal Balance-provider product, and a
// freshly-seeded starting balance.
func setupOrderPayTestFixtures(t *testing.T, startBalance float64) (owner, providerName, productName, buyerName string) {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner = "order_pay_it_org_" + suffix
	providerName = "order_pay_it_provider_" + suffix
	productName = "order_pay_it_product_" + suffix
	buyerName = "order_pay_it_buyer_" + suffix

	org := &Organization{
		Owner:           "admin",
		Name:            owner,
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     owner,
		BalanceCurrency: "USD",
	}
	if _, err := AddOrganization(org); err != nil {
		t.Fatalf("failed to create test organization: %v", err)
	}

	provider := &Provider{
		Owner:       "admin",
		Name:        providerName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Balance",
		Category:    "Payment",
		Type:        "Balance",
	}
	if _, err := AddProvider(provider); err != nil {
		t.Fatalf("failed to create test Balance provider: %v", err)
	}

	product := &Product{
		Owner:       owner,
		Name:        productName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Order Pay Test Widget",
		Price:       50,
		Currency:    "USD",
		Quantity:    1000,
		Providers:   []string{providerName},
		State:       "Ready",
	}
	if _, err := AddProduct(product); err != nil {
		t.Fatalf("failed to create test product: %v", err)
	}

	buyer := &User{
		Owner:           owner,
		Name:            buyerName,
		Id:              util.GenerateId(),
		CreatedTime:     util.GetCurrentTime(),
		UpdatedTime:     util.GetCurrentTime(),
		Type:            "normal-user",
		DisplayName:     "Order Pay Test Buyer",
		Balance:         startBalance,
		BalanceCurrency: "USD",
	}
	if _, err := ormer.Engine.Insert(buyer); err != nil {
		t.Fatalf("failed to create test buyer: %v", err)
	}

	return owner, providerName, productName, buyerName
}

func getTestUserBalance(t *testing.T, owner, name string) float64 {
	t.Helper()
	user, err := getUser(owner, name)
	if err != nil {
		t.Fatalf("failed to read back buyer: %v", err)
	}
	if user == nil {
		t.Fatalf("buyer %s/%s unexpectedly missing", owner, name)
	}
	return user.Balance
}

// TestPlaceOrderRejectsNonPositiveQuantity covers TC-D61BA51E: a standard
// buyer must never be able to increase their own store-credit balance by
// ordering a negative quantity of a product and paying via the internal
// Balance provider. A purchase must only ever debit the buyer.
func TestPlaceOrderRejectsNonPositiveQuantity(t *testing.T) {
	InitConfig()

	const startBalance = 200.0
	owner, providerName, productName, buyerName := setupOrderPayTestFixtures(t, startBalance)
	buyerUser := &User{Owner: owner, Name: buyerName}

	// POSITIVE CONTROL: a legitimate positive-quantity purchase must DEBIT
	// the buyer. If this fails, the test environment itself is unhealthy and
	// no conclusion can be drawn about the exploit below.
	legitOrder, err := PlaceOrder(owner, []ProductInfo{{Name: productName, Quantity: 1}}, buyerUser, "")
	if err != nil {
		t.Fatalf("HARNESS: could not place legitimate control order: %v", err)
	}
	if legitOrder.Price <= 0 {
		t.Fatalf("HARNESS: control order has non-positive price %v", legitOrder.Price)
	}
	if _, _, err := PayOrder(providerName, "", "", legitOrder, "en"); err != nil {
		t.Fatalf("HARNESS: could not pay legitimate control order: %v", err)
	}
	afterControlBalance := getTestUserBalance(t, owner, buyerName)
	expectedAfterControl := startBalance - legitOrder.Price
	if afterControlBalance != expectedAfterControl {
		t.Fatalf("POSITIVE CONTROL FAILED: expected balance %v after debit of %v, got %v -- environment is not behaving as a healthy baseline",
			expectedAfterControl, legitOrder.Price, afterControlBalance)
	}

	// EXPLOIT: ordering a negative quantity of the same product must be
	// rejected outright -- it must never be possible to create an order with
	// a negative price in the first place.
	exploitOrder, err := PlaceOrder(owner, []ProductInfo{{Name: productName, Quantity: -10}}, buyerUser, "")
	if err == nil {
		t.Fatalf("VULNERABLE: PlaceOrder accepted a negative quantity and created order %s with price %v (should have been rejected)",
			exploitOrder.GetId(), exploitOrder.Price)
	}

	// Invariant: the buyer's balance must be unchanged by the rejected
	// attempt -- no money was ever credited.
	balanceAfterExploitAttempt := getTestUserBalance(t, owner, buyerName)
	if balanceAfterExploitAttempt != afterControlBalance {
		t.Fatalf("VULNERABILITY CONFIRMED: buyer balance changed from %v to %v after a rejected negative-quantity order attempt",
			afterControlBalance, balanceAfterExploitAttempt)
	}
}

// TestPayOrderRejectsNonPositivePrice is defense-in-depth: even if an order
// somehow ends up persisted with a non-positive price (bypassing
// PlaceOrder's validation, e.g. via direct DB manipulation or a future
// regression), PayOrder must still refuse to pay it through the Balance
// provider rather than crediting the buyer.
func TestPayOrderRejectsNonPositivePrice(t *testing.T) {
	InitConfig()

	const startBalance = 200.0
	owner, providerName, productName, buyerName := setupOrderPayTestFixtures(t, startBalance)

	// Craft a "Created" order with a negative price directly, bypassing
	// PlaceOrder, to isolate PayOrder's own defense.
	orderName := fmt.Sprintf("order_%v", util.GenerateTimeId())
	order := &Order{
		Owner:       owner,
		Name:        orderName,
		DisplayName: orderName,
		CreatedTime: util.GetCurrentTime(),
		Products:    []string{productName},
		ProductInfos: []ProductInfo{
			{Owner: owner, Name: productName, Price: 50, Currency: "USD", Quantity: -10},
		},
		User:     buyerName,
		Price:    -500,
		Currency: "USD",
		State:    "Created",
	}
	if affected, err := AddOrder(order); err != nil || !affected {
		t.Fatalf("HARNESS: could not create crafted negative-price order: affected=%v err=%v", affected, err)
	}

	_, _, err := PayOrder(providerName, "", "", order, "en")
	if err == nil {
		balanceAfter := getTestUserBalance(t, owner, buyerName)
		t.Fatalf("VULNERABILITY CONFIRMED: PayOrder paid a negative-price order (price=%v) via the Balance provider without error, buyer balance is now %v (started at %v)",
			order.Price, balanceAfter, startBalance)
	}

	balanceAfter := getTestUserBalance(t, owner, buyerName)
	if balanceAfter != startBalance {
		t.Fatalf("VULNERABILITY CONFIRMED: buyer balance changed from %v to %v despite PayOrder returning an error",
			startBalance, balanceAfter)
	}
}
