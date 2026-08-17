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
	"testing"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

// setupOrderPayFixtures creates an isolated organization, buyer, non-recharge
// product and "Balance" payment provider for the order/payment regression
// tests below, and registers cleanup for all of them.
//
// Invariant under test (TC-4CD1CE43): a buyer must not be able to create an
// order with a negative price, and paying an order must never increase the
// buyer's stored balance.
func setupOrderPayFixtures(t *testing.T, startingBalance float64) (orgName string, user *User, product *Product, providerName string) {
	InitConfig()

	suffix := util.GenerateId()
	orgName = "org_order_pay_" + suffix
	userName := "user_order_pay_" + suffix
	productName := "product_order_pay_" + suffix
	providerName = "provider_order_pay_" + suffix

	organization := &Organization{
		Owner:           "admin",
		Name:            orgName,
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     orgName,
		BalanceCurrency: "USD",
	}
	if _, err := AddOrganization(organization); err != nil {
		t.Fatalf("failed to create test organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = deleteOrganization(organization)
	})

	provider := &Provider{
		Owner:       orgName,
		Name:        providerName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Balance",
		Category:    "Payment",
		Type:        "Balance",
	}
	if _, err := AddProvider(provider); err != nil {
		t.Fatalf("failed to create test provider: %v", err)
	}
	t.Cleanup(func() {
		_, _ = DeleteProvider(provider)
	})

	product = &Product{
		Owner:       orgName,
		Name:        productName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: productName,
		Currency:    "USD",
		Price:       10,
		Quantity:    999,
		IsRecharge:  false,
		Providers:   []string{providerName},
		State:       "Published",
	}
	if _, err := AddProduct(product); err != nil {
		t.Fatalf("failed to create test product: %v", err)
	}
	t.Cleanup(func() {
		_, _ = DeleteProduct(product)
	})

	user = &User{
		Owner:           orgName,
		Name:            userName,
		Id:              util.GenerateId(),
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     userName,
		Balance:         startingBalance,
		Currency:        "USD",
		BalanceCurrency: "USD",
	}
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	t.Cleanup(func() {
		// Delete the row directly rather than via DeleteUser: DeleteUser
		// drives the global Casbin group enforcer, which InitConfig (the
		// lightweight DB-only bootstrap used by this test) does not set up.
		_, _ = ormer.Engine.ID(core.PK{user.Owner, user.Name}).Delete(&User{})
	})

	return orgName, user, product, providerName
}

func getTestUserBalance(t *testing.T, owner, name string) float64 {
	t.Helper()
	u, err := getUser(owner, name)
	if err != nil {
		t.Fatalf("failed to reload test user: %v", err)
	}
	if u == nil {
		t.Fatalf("test user %s/%s not found", owner, name)
	}
	return u.Balance
}

// TestPlaceOrderRejectsNonPositiveQuantity asserts the invariant that a
// buyer must not be able to create an order with a negative (or zero)
// price by supplying a non-positive quantity for an ordinary (non-recharge)
// product. A legitimate positive-quantity order (the control) must still
// succeed and compute the correct price.
func TestPlaceOrderRejectsNonPositiveQuantity(t *testing.T) {
	orgName, user, product, _ := setupOrderPayFixtures(t, 100)

	// Control: a legitimate positive-quantity order must succeed.
	controlOrder, err := PlaceOrder(orgName, []ProductInfo{{Name: product.Name, Quantity: 2}}, user, "")
	if err != nil {
		t.Fatalf("expected legitimate quantity=2 order to succeed, got error: %v", err)
	}
	if controlOrder.Price != product.Price*2 {
		t.Fatalf("expected control order price to be %v, got %v", product.Price*2, controlOrder.Price)
	}
	t.Cleanup(func() { _, _ = DeleteOrder(controlOrder) })

	// Exploit: a negative quantity must be rejected outright, never
	// reaching order creation with a negative price.
	negativeOrder, err := PlaceOrder(orgName, []ProductInfo{{Name: product.Name, Quantity: -5}}, user, "")
	if err == nil {
		t.Cleanup(func() { _, _ = DeleteOrder(negativeOrder) })
		t.Fatalf("expected PlaceOrder to reject a negative quantity, but it created order %q with price %v", negativeOrder.Name, negativeOrder.Price)
	}

	// A zero quantity is equally invalid (produces a zero-price order for
	// a paid product) and must also be rejected.
	zeroOrder, err := PlaceOrder(orgName, []ProductInfo{{Name: product.Name, Quantity: 0}}, user, "")
	if err == nil {
		t.Cleanup(func() { _, _ = DeleteOrder(zeroOrder) })
		t.Fatalf("expected PlaceOrder to reject a zero quantity, but it created order %q with price %v", zeroOrder.Name, zeroOrder.Price)
	}
}

// TestPayOrderRejectsNegativePriceOrder asserts the second half of the
// invariant: paying an order must never increase the buyer's stored
// balance. It exercises PayOrder directly against a maliciously
// constructed negative-price order (as defense in depth, independent of
// whichever code path produced it - see TestPlaceOrderRejectsNonPositiveQuantity
// for the primary guard) and confirms the buyer's balance is left
// unchanged. A legitimate positive-price order (the control) must still be
// payable and correctly debit the buyer's balance.
func TestPayOrderRejectsNegativePriceOrder(t *testing.T) {
	orgName, user, product, providerName := setupOrderPayFixtures(t, 100)

	// Control: paying a legitimate positive-price order must succeed and
	// debit the buyer's balance by exactly the order price.
	controlOrder := &Order{
		Owner:        orgName,
		Name:         "order_control_" + util.GenerateId(),
		DisplayName:  "order_control",
		CreatedTime:  util.GetCurrentTime(),
		Products:     []string{product.Name},
		ProductInfos: []ProductInfo{{Owner: orgName, Name: product.Name, Price: product.Price, Currency: "USD", Quantity: 1}},
		User:         user.Name,
		Price:        product.Price,
		Currency:     "USD",
		State:        "Created",
	}
	if _, err := AddOrder(controlOrder); err != nil {
		t.Fatalf("failed to create control order: %v", err)
	}
	t.Cleanup(func() { _, _ = DeleteOrder(controlOrder) })

	balBeforeControl := getTestUserBalance(t, orgName, user.Name)
	if _, _, err := PayOrder(providerName, "localhost:8000", "", controlOrder, "en"); err != nil {
		t.Fatalf("expected legitimate order payment to succeed, got error: %v", err)
	}
	balAfterControl := getTestUserBalance(t, orgName, user.Name)
	if balAfterControl != balBeforeControl-product.Price {
		t.Fatalf("expected legitimate purchase to debit balance by %v: before=%v after=%v", product.Price, balBeforeControl, balAfterControl)
	}

	// Exploit: a negative-price order (as could otherwise be produced by a
	// negative-quantity purchase) must be rejected by PayOrder, and must
	// never increase the buyer's balance.
	maliciousOrder := &Order{
		Owner:        orgName,
		Name:         "order_malicious_" + util.GenerateId(),
		DisplayName:  "order_malicious",
		CreatedTime:  util.GetCurrentTime(),
		Products:     []string{product.Name},
		ProductInfos: []ProductInfo{{Owner: orgName, Name: product.Name, Price: product.Price, Currency: "USD", Quantity: -5}},
		User:         user.Name,
		Price:        -50,
		Currency:     "USD",
		State:        "Created",
	}
	if _, err := AddOrder(maliciousOrder); err != nil {
		t.Fatalf("failed to create malicious order fixture: %v", err)
	}
	t.Cleanup(func() { _, _ = DeleteOrder(maliciousOrder) })

	balBeforeExploit := getTestUserBalance(t, orgName, user.Name)
	_, _, err := PayOrder(providerName, "localhost:8000", "", maliciousOrder, "en")
	balAfterExploit := getTestUserBalance(t, orgName, user.Name)

	if err == nil {
		t.Fatalf("expected PayOrder to reject a negative-price order, but it succeeded (balance before=%v after=%v)", balBeforeExploit, balAfterExploit)
	}
	if balAfterExploit != balBeforeExploit {
		t.Fatalf("invariant violated: paying a rejected negative-price order still changed the buyer's balance: before=%v after=%v", balBeforeExploit, balAfterExploit)
	}
	if balAfterExploit > balBeforeExploit {
		t.Fatalf("invariant violated: buyer's balance increased from %v to %v by paying a negative-price order (minted from nothing)", balBeforeExploit, balAfterExploit)
	}
}
