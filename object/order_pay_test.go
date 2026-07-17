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
	"os"
	"path/filepath"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/util"
)

func TestPlaceOrderRejectsNonPositiveQuantities(t *testing.T) {
	initSqliteTestStore(t)

	owner := "niro-order-validation"
	productName := fmt.Sprintf("product_%s", util.GenerateId())
	product := &Product{
		Owner:       owner,
		Name:        productName,
		DisplayName: productName,
		Currency:    "USD",
		Price:       10,
		Quantity:    5,
		Providers:   []string{"provider-test"},
	}
	affected, err := AddProduct(product)
	if err != nil {
		t.Fatalf("AddProduct() error = %v", err)
	}
	if !affected {
		t.Fatal("AddProduct() affected = false")
	}
	t.Cleanup(func() {
		_, _ = DeleteProduct(product)
	})

	user := &User{Owner: owner, Name: "alice"}
	validOrder, err := PlaceOrder(owner, []ProductInfo{{
		Name:     productName,
		Quantity: 1,
	}}, user, "")
	if err != nil {
		t.Fatalf("positive control PlaceOrder(quantity=1) error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = DeleteOrder(validOrder)
	})
	if validOrder.Price != 10 || len(validOrder.ProductInfos) != 1 || validOrder.ProductInfos[0].Quantity != 1 {
		t.Fatalf("positive control created unexpected order: price=%v productInfos=%+v", validOrder.Price, validOrder.ProductInfos)
	}

	for _, quantity := range []int{-3, 0} {
		t.Run(fmt.Sprintf("quantity_%d", quantity), func(t *testing.T) {
			order, err := PlaceOrder(owner, []ProductInfo{{
				Name:     productName,
				Quantity: quantity,
			}}, user, "")
			if err == nil {
				t.Cleanup(func() {
					_, _ = DeleteOrder(order)
				})
				t.Fatalf("PlaceOrder(quantity=%d) created order %s with price %v; want controlled rejection", quantity, order.Name, order.Price)
			}
		})
	}
}

func initSqliteTestStore(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	config := filepath.Join(dir, "app.conf")
	dbPath := filepath.Join(dir, "casdoor.db")
	if err := os.WriteFile(config, []byte(fmt.Sprintf(`
appname = casdoor
runmode = test
copyrequestbody = true
driverName = sqlite
dataSourceName = %s
dbName =
tableNamePrefix =
showSql = false
defaultLanguage = en
`, dbPath)), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	if err := web.LoadAppConfig("ini", config); err != nil {
		t.Fatalf("LoadAppConfig() error = %v", err)
	}
	createDatabase = false
	InitAdapter()
	CreateTables()
}
