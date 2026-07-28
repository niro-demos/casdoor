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

	"github.com/casdoor/casdoor/util"
)

// seedNegQtyOrderFixtures creates an isolated user + product pair (under the
// built-in organization) so this test never touches shared fixtures or other
// tests' data, and returns their identifiers.
func seedNegQtyOrderFixtures(t *testing.T, balance float64) (owner, userName, productName string) {
	t.Helper()

	owner = "built-in"
	suffix := util.GenerateId()
	userName = fmt.Sprintf("negqty-buyer-%s", suffix)
	productName = fmt.Sprintf("negqty-widget-%s", suffix)

	user := &User{
		Owner:       owner,
		Name:        userName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		Type:        "normal-user",
		DisplayName: "NegQty Buyer",
		Balance:     balance,
	}
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	product := &Product{
		Owner:       owner,
		Name:        productName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "NegQty Widget",
		Currency:    "USD",
		Price:       100,
		Quantity:    1000,
		Sold:        0,
		Providers:   []string{"provider_balance"},
		State:       "Published",
	}
	if _, err := ormer.Engine.Insert(product); err != nil {
		t.Fatalf("failed to seed product: %v", err)
	}

	return owner, userName, productName
}

func reloadUserBalance(t *testing.T, owner, userName string) float64 {
	t.Helper()
	u, err := GetUser(util.GetId(owner, userName))
	if err != nil || u == nil {
		t.Fatalf("failed to reload user: %v", err)
	}
	return u.Balance
}

// TestPlaceOrderPositiveQuantityControl is the legitimate-request control: a
// normal, positive-quantity order must be accepted and priced as
// unitPrice*quantity. If this fails, the harness/fixtures are broken -- not
// the invariant under test.
func TestPlaceOrderPositiveQuantityControl(t *testing.T) {
	InitConfig()
	InitDb()

	owner, userName, productName := seedNegQtyOrderFixtures(t, 1000)
	user, err := GetUser(util.GetId(owner, userName))
	if err != nil || user == nil {
		t.Fatalf("failed to fetch seeded user: %v", err)
	}

	order, err := PlaceOrder(owner, []ProductInfo{{Owner: owner, Name: productName, Quantity: 3}}, user, "")
	if err != nil {
		t.Fatalf("expected legitimate positive-quantity order to be accepted, got error: %v", err)
	}
	if order.Price != 300 {
		t.Errorf("expected order price 300 (unitPrice 100 * quantity 3), got %v", order.Price)
	}
}

// TestPlaceOrderRejectsNonPositiveQuantity is the regression test for
// TC-91E9FCD7: PlaceOrder must reject a non-positive quantity for a
// non-recharge product instead of accepting it and computing a
// zero/negative order price.
func TestPlaceOrderRejectsNonPositiveQuantity(t *testing.T) {
	InitConfig()
	InitDb()

	owner, userName, productName := seedNegQtyOrderFixtures(t, 1000)
	user, err := GetUser(util.GetId(owner, userName))
	if err != nil || user == nil {
		t.Fatalf("failed to fetch seeded user: %v", err)
	}

	for _, quantity := range []int{0, -1, -5, -10} {
		quantity := quantity
		t.Run(fmt.Sprintf("quantity_%d", quantity), func(t *testing.T) {
			order, err := PlaceOrder(owner, []ProductInfo{{Owner: owner, Name: productName, Quantity: quantity}}, user, "")
			if err == nil {
				t.Fatalf("invariant violated: expected PlaceOrder to reject quantity=%d, but it was accepted with price=%v", quantity, order.Price)
			}
			if order != nil {
				t.Errorf("expected no order to be returned alongside the error, got: %+v", order)
			}
		})
	}
}

// TestPlaceOrderNegativeQuantityNeverCreditsBalance is the end-to-end
// regression test for TC-91E9FCD7: a standard user must not be able to
// increase their own account balance by placing an order with a negative
// product quantity and paying it through the internal Balance provider.
// Since the fix rejects the order at PlaceOrder time, PayOrder is never
// reached and the buyer's balance must be completely unaffected.
func TestPlaceOrderNegativeQuantityNeverCreditsBalance(t *testing.T) {
	InitConfig()
	InitDb()

	const startingBalance = 99400.0
	owner, userName, productName := seedNegQtyOrderFixtures(t, startingBalance)
	user, err := GetUser(util.GetId(owner, userName))
	if err != nil || user == nil {
		t.Fatalf("failed to fetch seeded user: %v", err)
	}

	balanceBefore := reloadUserBalance(t, owner, userName)

	order, err := PlaceOrder(owner, []ProductInfo{{Owner: owner, Name: productName, Quantity: -5}}, user, "")
	if err == nil {
		// Only reachable if PlaceOrder regresses back to accepting a negative
		// quantity; drive the exploit to completion so the failure clearly
		// shows the balance-minting impact rather than stopping at "no error".
		payment, _, payErr := PayOrder("provider_balance", "http://localhost:8000", "", order, "en")
		balanceAfter := reloadUserBalance(t, owner, userName)
		t.Fatalf("invariant violated: negative-quantity order was accepted (price=%v) and paying it via Balance (err=%v, payment=%+v) moved the buyer's balance from %v to %v",
			order.Price, payErr, payment, balanceBefore, balanceAfter)
	}

	balanceAfter := reloadUserBalance(t, owner, userName)
	if balanceAfter != balanceBefore {
		t.Errorf("invariant violated: buyer's balance changed from %v to %v even though the order was rejected", balanceBefore, balanceAfter)
	}
}

// TestPayOrderRejectsNegativePriceOrder is the defense-in-depth regression
// test for TC-91E9FCD7: even if an order with a negative price reached
// PayOrder by some other path than PlaceOrder, paying it through the
// internal Balance provider must never credit the buyer's balance.
func TestPayOrderRejectsNegativePriceOrder(t *testing.T) {
	InitConfig()
	InitDb()

	const startingBalance = 99400.0
	owner, userName, productName := seedNegQtyOrderFixtures(t, startingBalance)

	order := &Order{
		Owner:       owner,
		Name:        fmt.Sprintf("negqty-order-%s", util.GenerateId()),
		DisplayName: "NegQty Order",
		CreatedTime: util.GetCurrentTime(),
		Products:    []string{productName},
		ProductInfos: []ProductInfo{{
			Owner:    owner,
			Name:     productName,
			Price:    100,
			Currency: "USD",
			Quantity: -5,
		}},
		User:     userName,
		Price:    -500,
		Currency: "USD",
		State:    "Created",
	}
	affected, err := AddOrder(order)
	if err != nil || !affected {
		t.Fatalf("failed to seed negative-price order: affected=%v err=%v", affected, err)
	}

	balanceBefore := reloadUserBalance(t, owner, userName)

	o, err := GetOrder(order.GetId())
	if err != nil || o == nil {
		t.Fatalf("failed to reload seeded order: %v", err)
	}

	payment, _, err := PayOrder("provider_balance", "http://localhost:8000", "", o, "en")
	balanceAfter := reloadUserBalance(t, owner, userName)

	if err == nil {
		t.Fatalf("invariant violated: PayOrder accepted a negative-price order (payment=%+v) and moved the buyer's balance from %v to %v",
			payment, balanceBefore, balanceAfter)
	}
	if balanceAfter != balanceBefore {
		t.Errorf("invariant violated: buyer's balance changed from %v to %v even though PayOrder returned an error", balanceBefore, balanceAfter)
	}
}
