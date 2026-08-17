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

// payOrderRaceFixtures holds a self-contained, uniquely-named organization,
// buyer and recharge product so this test never depends on, or collides
// with, any other seeded data in the shared test database.
type payOrderRaceFixtures struct {
	orgName      string
	userName     string
	productName  string
	providerName string
	user         *User
}

func setupPayOrderRaceFixtures(t *testing.T) *payOrderRaceFixtures {
	t.Helper()

	suffix := util.GenerateId()
	orgName := fmt.Sprintf("test-org-payrace-%s", suffix)
	userName := "buyer"
	productName := fmt.Sprintf("product-recharge-%s", suffix)
	providerName := fmt.Sprintf("provider-dummy-%s", suffix)

	organization := &Organization{
		Owner:           "admin",
		Name:            orgName,
		DisplayName:     orgName,
		CreatedTime:     util.GetCurrentTime(),
		BalanceCurrency: "USD",
	}
	if affected, err := AddOrganization(organization); err != nil || !affected {
		t.Fatalf("failed to create test organization: affected=%v err=%v", affected, err)
	}

	user := &User{
		Owner:       orgName,
		Name:        userName,
		CreatedTime: util.GetCurrentTime(),
		Id:          util.GenerateId(),
		Balance:     0,
	}
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	provider := &Provider{
		Owner:       orgName,
		Name:        providerName,
		DisplayName: providerName,
		CreatedTime: util.GetCurrentTime(),
		Category:    "Payment",
		Type:        "Dummy",
	}
	if affected, err := AddProvider(provider); err != nil || !affected {
		t.Fatalf("failed to create test provider: affected=%v err=%v", affected, err)
	}

	product := &Product{
		Owner:       orgName,
		Name:        productName,
		DisplayName: productName,
		CreatedTime: util.GetCurrentTime(),
		Currency:    "USD",
		Price:       5,
		Quantity:    1000,
		IsRecharge:  true,
		Providers:   []string{providerName},
		State:       "Published",
	}
	if affected, err := AddProduct(product); err != nil || !affected {
		t.Fatalf("failed to create test product: affected=%v err=%v", affected, err)
	}

	loadedUser, err := GetUser(util.GetId(orgName, userName))
	if err != nil || loadedUser == nil {
		t.Fatalf("failed to load test user: %v", err)
	}

	return &payOrderRaceFixtures{
		orgName:      orgName,
		userName:     userName,
		productName:  productName,
		providerName: providerName,
		user:         loadedUser,
	}
}

func (f *payOrderRaceFixtures) placeOrder(t *testing.T) *Order {
	t.Helper()

	order, err := PlaceOrder(f.orgName, []ProductInfo{{Name: f.productName, Price: 5, Quantity: 1}}, f.user, "")
	if err != nil {
		t.Fatalf("failed to place order: %v", err)
	}
	return order
}

func (f *payOrderRaceFixtures) getBalance(t *testing.T) float64 {
	t.Helper()

	user, err := GetUser(util.GetId(f.orgName, f.userName))
	if err != nil || user == nil {
		t.Fatalf("failed to reload user: %v", err)
	}
	return user.Balance
}

// TestPayOrderSingleAttemptPaysAndCreditsOnce is the positive control: a lone,
// non-racing pay-order call against a freshly created order must still work
// end to end (create exactly one Payment, and crediting the buyer exactly the
// order price once it's confirmed). This must stay green before and after the
// concurrency fix -- it proves the fix does not break the legitimate flow.
func TestPayOrderSingleAttemptPaysAndCreditsOnce(t *testing.T) {
	InitConfig()

	f := setupPayOrderRaceFixtures(t)
	order := f.placeOrder(t)
	balanceBefore := f.getBalance(t)

	payment, _, err := PayOrder(f.providerName, "example.com", "", order, "en")
	if err != nil {
		t.Fatalf("expected a lone pay-order attempt to succeed, got error: %v", err)
	}

	if _, err := NotifyPayment(nil, f.orgName, payment.Name, "en"); err != nil {
		t.Fatalf("failed to confirm payment: %v", err)
	}

	var payments []*Payment
	if err := ormer.Engine.Find(&payments, &Payment{Owner: f.orgName, Order: order.Name}); err != nil {
		t.Fatalf("failed to list payments for order: %v", err)
	}
	if len(payments) != 1 {
		t.Fatalf("expected exactly 1 payment for the order, got %d", len(payments))
	}

	balanceAfter := f.getBalance(t)
	if delta := balanceAfter - balanceBefore; delta != order.Price {
		t.Fatalf("expected balance to increase by exactly the order price (%v), got delta %v", order.Price, delta)
	}
}

// TestPayOrderConcurrentPaymentsCreateOnlyOnePayment reproduces TC-AE8CD705:
// firing multiple concurrent pay-order requests against a single "Created"
// order must result in at most one Payment being created for that order, and
// confirming it must credit the buyer's balance exactly once -- never once
// per concurrent attempt. Before the fix, PayOrder's read of order.State and
// its later AddPayment insert race, so every concurrent caller passes the
// "Created" check and each creates its own Payment; after the fix, an atomic
// claim on the order allows only the first caller through.
func TestPayOrderConcurrentPaymentsCreateOnlyOnePayment(t *testing.T) {
	InitConfig()

	f := setupPayOrderRaceFixtures(t)
	order := f.placeOrder(t)
	balanceBefore := f.getBalance(t)

	const concurrentAttempts = 5
	var wg sync.WaitGroup
	payments := make([]*Payment, concurrentAttempts)
	errs := make([]error, concurrentAttempts)

	for i := 0; i < concurrentAttempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Mirror the HTTP handler: each request loads its own fresh copy of
			// the order before calling PayOrder.
			o, gErr := GetOrder(order.GetId())
			if gErr != nil || o == nil {
				errs[i] = fmt.Errorf("failed to reload order: %v", gErr)
				return
			}
			payment, _, pErr := PayOrder(f.providerName, "example.com", "", o, "en")
			payments[i] = payment
			errs[i] = pErr
		}(i)
	}
	wg.Wait()

	successCount := 0
	for i := 0; i < concurrentAttempts; i++ {
		if errs[i] == nil {
			successCount++
		}
	}
	if successCount != 1 {
		t.Fatalf("invariant violated: expected exactly 1 of %d concurrent PayOrder calls to succeed, got %d successes (errors: %v)", concurrentAttempts, successCount, errs)
	}

	// Confirm the invariant at the data level too: exactly one Payment row must
	// exist for the order, regardless of how many callers raced for it.
	var dbPayments []*Payment
	if err := ormer.Engine.Find(&dbPayments, &Payment{Owner: f.orgName, Order: order.Name}); err != nil {
		t.Fatalf("failed to list payments for order: %v", err)
	}
	if len(dbPayments) != 1 {
		t.Fatalf("invariant violated: expected exactly 1 Payment row for the order, found %d", len(dbPayments))
	}

	// Confirm every payment a client could have observed as "ok" via
	// notify-payment (the public callback), then assert the buyer was credited
	// exactly once for the order, not once per attempt.
	for i := 0; i < concurrentAttempts; i++ {
		if payments[i] == nil {
			continue
		}
		if _, err := NotifyPayment(nil, f.orgName, payments[i].Name, "en"); err != nil {
			t.Fatalf("failed to confirm payment %s: %v", payments[i].Name, err)
		}
	}

	balanceAfter := f.getBalance(t)
	if delta := balanceAfter - balanceBefore; delta != order.Price {
		t.Fatalf("invariant violated: expected balance to increase by exactly the order price (%v) once, got delta %v (%vx)", order.Price, delta, delta/order.Price)
	}
}
