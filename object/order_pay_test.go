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
	"path/filepath"
	"testing"
)

func TestPlaceOrderRejectsNonPositiveQuantitiesWithoutPersistingOrder(t *testing.T) {
	setupPlaceOrderTestStore(t)

	product := &Product{
		Owner:       "test-owner",
		Name:        "test-product",
		DisplayName: "Test Product",
		Currency:    "USD",
		Price:       7.25,
		Quantity:    100,
		Providers:   []string{"test-provider"},
		State:       "Published",
	}
	if affected, err := AddProduct(product); err != nil {
		t.Fatalf("AddProduct() error = %v", err)
	} else if !affected {
		t.Fatal("AddProduct() affected no rows")
	}

	user := &User{Name: "alice"}

	order, err := PlaceOrder(product.Owner, []ProductInfo{{
		Name:     product.Name,
		Quantity: 1,
	}}, user, "")
	if err != nil {
		t.Fatalf("PlaceOrder() with quantity 1 error = %v", err)
	}
	if order.Price != product.Price {
		t.Fatalf("PlaceOrder() with quantity 1 price = %v, want %v", order.Price, product.Price)
	}
	if len(order.ProductInfos) != 1 || order.ProductInfos[0].Quantity != 1 {
		t.Fatalf("PlaceOrder() with quantity 1 productInfos = %+v", order.ProductInfos)
	}

	orderCount := countOrders(t, product.Owner)
	for _, quantity := range []int{0, -1} {
		t.Run("quantity", func(t *testing.T) {
			if _, err := PlaceOrder(product.Owner, []ProductInfo{{
				Name:     product.Name,
				Quantity: quantity,
			}}, user, ""); err == nil {
				t.Fatalf("PlaceOrder() with quantity %d succeeded, want error", quantity)
			}

			if got := countOrders(t, product.Owner); got != orderCount {
				t.Fatalf("order count after quantity %d = %d, want %d", quantity, got, orderCount)
			}
		})
	}
}

func setupPlaceOrderTestStore(t *testing.T) {
	t.Helper()

	previousOrmer := ormer
	t.Cleanup(func() {
		if ormer != nil {
			ormer.close()
		}
		ormer = previousOrmer
	})

	var err error
	ormer, err = NewAdapter("sqlite", filepath.Join(t.TempDir(), "casdoor-order-test.db"), "")
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}
	if err := ormer.Engine.Sync2(new(Provider), new(Product), new(Order)); err != nil {
		t.Fatalf("Sync2() error = %v", err)
	}
}

func countOrders(t *testing.T, owner string) int64 {
	t.Helper()

	count, err := ormer.Engine.Count(&Order{Owner: owner})
	if err != nil {
		t.Fatalf("Count(Order) error = %v", err)
	}
	return count
}
