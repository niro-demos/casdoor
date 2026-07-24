// Copyright 2025 The Casdoor Authors. All Rights Reserved.
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

// Security invariant (TC-87A4631F):
//
//	A customer must not be able to place an order whose total price is negative
//	or zero by supplying a negative (or zero) product quantity.
//
// buildOrderProductInfos is the pure pricing/validation core of PlaceOrder. It
// runs with no DB, so this regression test exercises the exact vulnerable code
// path hermetically. A green legitimate control is paired with each exploit
// case so a red failure is provably the missing quantity bound, not a broken
// setup.
func TestBuildOrderProductInfos_QuantityMustBePositive(t *testing.T) {
	const owner = "acme"
	const product = "acme-prod-2"

	productMap := map[string]Product{
		product: {
			Owner:      owner,
			Name:       product,
			Price:      5.0,
			Currency:   "USD",
			Quantity:   1000, // in stock
			IsRecharge: false,
		},
	}

	line := func(qty int) []ProductInfo {
		return []ProductInfo{{Owner: owner, Name: product, Quantity: qty}}
	}

	// POSITIVE CONTROL: a legitimate order (quantity 2) must be accepted with a
	// positive price. If this fails, the test setup is broken, not the invariant.
	infos, price, err := buildOrderProductInfos(owner, line(2), productMap)
	if err != nil {
		t.Fatalf("control: legitimate order (quantity 2) was rejected: %v — baseline is broken", err)
	}
	if price != 10.0 {
		t.Fatalf("control: legitimate order (quantity 2) produced price %.2f, want 10.00 — baseline is broken", price)
	}
	if len(infos) != 1 {
		t.Fatalf("control: expected 1 product info, got %d", len(infos))
	}

	// EXPLOIT 1: a negative-quantity order must be REJECTED. On vulnerable code
	// it is accepted with price -5000, violating the invariant.
	if _, price, err := buildOrderProductInfos(owner, line(-1000), productMap); err == nil {
		t.Fatalf("invariant violated: negative-quantity order accepted with price %.2f "+
			"(a customer can create a negative-total order); expected rejection", price)
	}

	// EXPLOIT 2: a zero-quantity order must also be REJECTED (zero-total order).
	if _, price, err := buildOrderProductInfos(owner, line(0), productMap); err == nil {
		t.Fatalf("invariant violated: zero-quantity order accepted with price %.2f; expected rejection", price)
	}
}
