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

package object

import (
	"testing"
)

// Regression tests for the negative-quantity balance-minting vulnerability.
//
// Invariant: a user must never be able to construct an order whose total price is
// negative. A negative price flows into the Balance payment provider as
// Transaction.Amount = -order.Price, i.e. a positive wallet credit, letting any
// authenticated user mint unlimited balance by ordering a negative quantity.
//
// buildOrderProductInfos is the single choke point that computes the order price
// from the requested line items, so it is where the invariant is enforced and
// where we assert it here. These tests are pure (no database) and mirror what the
// live PoC (niro/findings/TC-D8232ABE) exercises over the REST API.

func newProductMap(products ...Product) map[string]Product {
	m := make(map[string]Product, len(products))
	for _, p := range products {
		m[p.Name] = p
	}
	return m
}

// TestBuildOrderProductInfos_RejectsNegativeQuantity is the core regression test:
// a standard (non-recharge) product ordered with a negative quantity must be
// rejected, never produce a negative order price.
func TestBuildOrderProductInfos_RejectsNegativeQuantity(t *testing.T) {
	owner := "org-alpha"
	productMap := newProductMap(Product{
		Owner:      owner,
		Name:       "product_test_alpha",
		Price:      100,
		Currency:   "USD",
		IsRecharge: false,
	})

	req := []ProductInfo{
		{Name: "product_test_alpha", Price: 100, Quantity: -5},
	}

	_, orderPrice, err := buildOrderProductInfos(owner, req, productMap)
	if err == nil {
		t.Fatalf("INVARIANT VIOLATED: negative quantity accepted, orderPrice=%.2f "+
			"(this negative price becomes a positive Balance-wallet credit)", orderPrice)
	}
}

// TestBuildOrderProductInfos_RejectsZeroQuantity ensures a zero quantity (which
// would also let free/near-free abuse through and produce a $0 order) is rejected.
func TestBuildOrderProductInfos_RejectsZeroQuantity(t *testing.T) {
	owner := "org-alpha"
	productMap := newProductMap(Product{
		Owner:    owner,
		Name:     "product_test_alpha",
		Price:    100,
		Currency: "USD",
	})

	req := []ProductInfo{
		{Name: "product_test_alpha", Price: 100, Quantity: 0},
	}

	if _, _, err := buildOrderProductInfos(owner, req, productMap); err == nil {
		t.Fatalf("INVARIANT VIOLATED: zero quantity accepted")
	}
}

// TestBuildOrderProductInfos_RejectsNegativeInMultiItemOrder ensures a single
// negative line item cannot be hidden behind legitimate positive ones to drag the
// total negative.
func TestBuildOrderProductInfos_RejectsNegativeInMultiItemOrder(t *testing.T) {
	owner := "org-alpha"
	productMap := newProductMap(
		Product{Owner: owner, Name: "p_cheap", Price: 10, Currency: "USD"},
		Product{Owner: owner, Name: "p_dear", Price: 100, Currency: "USD"},
	)

	req := []ProductInfo{
		{Name: "p_cheap", Price: 10, Quantity: 1},
		{Name: "p_dear", Price: 100, Quantity: -5}, // would drag total to -490
	}

	_, orderPrice, err := buildOrderProductInfos(owner, req, productMap)
	if err == nil {
		t.Fatalf("INVARIANT VIOLATED: negative quantity in multi-item order accepted, orderPrice=%.2f", orderPrice)
	}
}

// TestBuildOrderProductInfos_AllowsLegitimatePositiveOrder is the paired healthy
// baseline (positive control): a normal positive-quantity order must still succeed
// and price correctly, proving the failures above are the invariant firing and not
// a broken setup.
func TestBuildOrderProductInfos_AllowsLegitimatePositiveOrder(t *testing.T) {
	owner := "org-alpha"
	productMap := newProductMap(Product{
		Owner:    owner,
		Name:     "product_test_alpha",
		Price:    100,
		Currency: "USD",
	})

	req := []ProductInfo{
		{Name: "product_test_alpha", Price: 100, Quantity: 3},
	}

	infos, orderPrice, err := buildOrderProductInfos(owner, req, productMap)
	if err != nil {
		t.Fatalf("legitimate positive-quantity order rejected: %v", err)
	}
	if orderPrice != 300 {
		t.Fatalf("expected orderPrice=300 for qty=3 @ $100, got %.2f", orderPrice)
	}
	if len(infos) != 1 || infos[0].Quantity != 3 {
		t.Fatalf("unexpected product infos: %+v", infos)
	}
}

// TestBuildOrderProductInfos_RechargeStillGuardsPositiveQuantity confirms the
// existing recharge custom-price guard is preserved and a recharge product also
// requires a positive quantity.
func TestBuildOrderProductInfos_RechargeStillGuardsPositiveQuantity(t *testing.T) {
	owner := "org-alpha"
	productMap := newProductMap(Product{
		Owner:      owner,
		Name:       "recharge",
		Currency:   "USD",
		IsRecharge: true,
	})

	// Negative quantity on a recharge product must also be rejected.
	if _, _, err := buildOrderProductInfos(owner, []ProductInfo{
		{Name: "recharge", Price: 50, IsRecharge: true, Quantity: -1},
	}, productMap); err == nil {
		t.Fatalf("INVARIANT VIOLATED: negative quantity on recharge product accepted")
	}

	// The pre-existing non-positive custom-price guard must still hold.
	if _, _, err := buildOrderProductInfos(owner, []ProductInfo{
		{Name: "recharge", Price: 0, IsRecharge: true, Quantity: 1},
	}, productMap); err == nil {
		t.Fatalf("recharge product with non-positive custom price was accepted")
	}

	// A legitimate recharge line item still succeeds.
	_, orderPrice, err := buildOrderProductInfos(owner, []ProductInfo{
		{Name: "recharge", Price: 50, IsRecharge: true, Quantity: 2},
	}, productMap)
	if err != nil {
		t.Fatalf("legitimate recharge order rejected: %v", err)
	}
	if orderPrice != 100 {
		t.Fatalf("expected recharge orderPrice=100 for qty=2 @ $50, got %.2f", orderPrice)
	}
}
