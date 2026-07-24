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
	"strings"
	"testing"
)

func TestValidateOrderProductInfosRejectsNonPositiveQuantity(t *testing.T) {
	tests := []struct {
		name         string
		productInfos []ProductInfo
	}{
		{
			name: "place order request with negative quantity",
			productInfos: []ProductInfo{
				{Name: "test-product", Quantity: -1},
			},
		},
		{
			name: "place order request with zero quantity",
			productInfos: []ProductInfo{
				{Name: "test-product", Quantity: 0},
			},
		},
		{
			name: "persisted order with invalid quantity",
			productInfos: []ProductInfo{
				{Owner: "test", Name: "test-product", Price: 10, Quantity: -1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOrderProductInfos(tt.productInfos)
			if err == nil {
				t.Fatal("expected non-positive quantity to be rejected")
			}
			if !strings.Contains(err.Error(), "quantity") {
				t.Fatalf("expected quantity validation error, got %q", err.Error())
			}
		})
	}
}

func TestValidateOrderProductInfosAllowsPositiveQuantity(t *testing.T) {
	err := validateOrderProductInfos([]ProductInfo{
		{Name: "test-product", Quantity: 1},
		{Name: "test-recharge", Quantity: 2, Price: 20, IsRecharge: true},
	})
	if err != nil {
		t.Fatalf("expected positive quantities to be allowed, got %v", err)
	}
}
