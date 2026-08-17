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
	"encoding/json"
	"testing"

	"github.com/casdoor/casdoor/pp"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

// TestNotifyPaymentRejectsNonBuyerOnDummyProvider is a regression test for
// TC-2E650006: /api/notify-payment is a public, unauthenticated route (a
// requirement for real payment-gateway webhooks), and the built-in Dummy
// payment provider's Notify() (pp/dummy.go) unconditionally reports "Paid"
// with no authoritative check of its own, unlike Alipay/PayPal, which
// re-verify with the gateway using server-held credentials. Before this fix,
// NotifyPayment trusted that verdict from *any* caller, so an outside party
// who was not the buyer -- not even authenticated -- could force someone
// else's order to "Paid" by guessing/knowing its owner/payment name.
//
// The invariant under test: an outside party who is not the payment's buyer
// must not be able to force that payment/order into "Paid" via the Dummy
// provider. The payment's rightful buyer notifying it is a distinct,
// already-accepted behavior (see niro/accepted-behaviors.yaml) and must keep
// working -- that's the paired positive control below.
func TestNotifyPaymentRejectsNonBuyerOnDummyProvider(t *testing.T) {
	InitConfig()

	suffix := util.GenerateId()[:8]
	owner := "notify_test_org_" + suffix
	buyerName := "buyer_" + suffix
	buyerSessionUser := util.GetId(owner, buyerName)
	providerName := "provider_dummy_test_" + suffix
	productName := "product_test_" + suffix
	const (
		price    = 10.0
		currency = "USD"
	)

	provider := &Provider{
		Owner:    owner,
		Name:     providerName,
		Category: "Payment",
		Type:     "Dummy",
	}
	product := &Product{
		Owner:    owner,
		Name:     productName,
		Currency: currency,
		Price:    price,
		Quantity: 5,
	}
	buyer := &User{
		Owner: owner,
		Name:  buyerName,
		Id:    "id_" + buyerName,
	}

	if _, err := ormer.Engine.Insert(provider); err != nil {
		t.Fatalf("failed to seed provider fixture: %v", err)
	}
	if _, err := ormer.Engine.Insert(product); err != nil {
		t.Fatalf("failed to seed product fixture: %v", err)
	}
	if _, err := ormer.Engine.Insert(buyer); err != nil {
		t.Fatalf("failed to seed buyer fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.ID(core.PK{owner, providerName}).Delete(&Provider{})
		_, _ = ormer.Engine.ID(core.PK{owner, productName}).Delete(&Product{})
		_, _ = ormer.Engine.ID(core.PK{owner, buyerName}).Delete(&User{})
	})

	// newFixture creates a fresh Created order+payment pair owned by the
	// buyer, mirroring what object.Pay() would have produced via the Dummy
	// provider. It returns cleanup so each sub-test's rows are removed
	// regardless of outcome.
	newFixture := func(t *testing.T, label string) (*Order, *Payment) {
		t.Helper()

		orderName := "order_" + label + "_" + suffix
		paymentName := "payment_" + label + "_" + suffix

		outOrderIdBytes, err := json.Marshal(pp.DummyOrderInfo{Price: price, Currency: currency})
		if err != nil {
			t.Fatalf("failed to encode dummy out-order id: %v", err)
		}

		order := &Order{
			Owner: owner,
			Name:  orderName,
			Products: []string{
				productName,
			},
			ProductInfos: []ProductInfo{
				{Owner: owner, Name: productName, Price: price, Currency: currency, Quantity: 1},
			},
			User:     buyerName,
			Payment:  paymentName,
			Price:    price,
			Currency: currency,
			State:    "Created",
		}
		payment := &Payment{
			Owner:    owner,
			Name:     paymentName,
			Provider: providerName,
			Type:     "Dummy",
			Products: []string{
				productName,
			},
			Currency:   currency,
			Price:      price,
			User:       buyerName,
			Order:      orderName,
			OutOrderId: string(outOrderIdBytes),
			State:      pp.PaymentStateCreated,
		}

		if _, err := ormer.Engine.Insert(order); err != nil {
			t.Fatalf("failed to seed order fixture: %v", err)
		}
		if _, err := ormer.Engine.Insert(payment); err != nil {
			t.Fatalf("failed to seed payment fixture: %v", err)
		}
		t.Cleanup(func() {
			_, _ = ormer.Engine.ID(core.PK{owner, orderName}).Delete(&Order{})
			_, _ = ormer.Engine.ID(core.PK{owner, paymentName}).Delete(&Payment{})
			_, _ = ormer.Engine.Where("owner = ? AND payment = ?", owner, paymentName).Delete(&Transaction{})
		})

		return order, payment
	}

	t.Run("outside party (unauthenticated) cannot force the order to Paid", func(t *testing.T) {
		order, payment := newFixture(t, "anon")

		// Attack: notify with zero session identity, exactly what an
		// anonymous POST to /api/notify-payment/:owner/:payment produces.
		_, err := NotifyPayment([]byte("{}"), owner, payment.Name, "", "en")
		if err == nil {
			t.Fatal("invariant violated: an unauthenticated caller's notify-payment call was accepted")
		}

		reloadedOrder, getErr := getOrder(owner, order.Name)
		if getErr != nil {
			t.Fatalf("failed to reload order: %v", getErr)
		}
		if reloadedOrder.State == "Paid" {
			t.Fatalf("invariant violated: order state changed to %q via an unauthenticated notify-payment call", reloadedOrder.State)
		}
		if reloadedOrder.State != "Created" {
			t.Fatalf("order should remain untouched (\"Created\"), got %q", reloadedOrder.State)
		}
	})

	t.Run("outside party (authenticated as someone else) cannot force the order to Paid", func(t *testing.T) {
		order, payment := newFixture(t, "other")

		otherOwner := "notify_test_org_other_" + suffix
		otherSessionUser := util.GetId(otherOwner, "mallory_"+suffix)

		_, err := NotifyPayment([]byte("{}"), owner, payment.Name, otherSessionUser, "en")
		if err == nil {
			t.Fatal("invariant violated: an unrelated authenticated caller's notify-payment call was accepted")
		}

		reloadedOrder, getErr := getOrder(owner, order.Name)
		if getErr != nil {
			t.Fatalf("failed to reload order: %v", getErr)
		}
		if reloadedOrder.State == "Paid" {
			t.Fatalf("invariant violated: order state changed to %q via an unrelated third party's notify-payment call", reloadedOrder.State)
		}
	})

	// Positive control: the payment's rightful buyer notifying their own
	// Dummy-provider payment must keep working (niro/accepted-behaviors.yaml
	// already accepts this as intended self-service behavior). If this case
	// broke too, the two cases above would prove nothing about the
	// authorization check being isolated to non-buyers.
	t.Run("the rightful buyer can still notify their own payment", func(t *testing.T) {
		order, payment := newFixture(t, "buyer")

		notified, err := NotifyPayment([]byte("{}"), owner, payment.Name, buyerSessionUser, "en")
		if err != nil {
			t.Fatalf("the rightful buyer's own notify-payment call should succeed, got error: %v", err)
		}
		if notified.State != pp.PaymentStatePaid {
			t.Fatalf("expected the buyer's payment to become %q, got %q", pp.PaymentStatePaid, notified.State)
		}

		reloadedOrder, getErr := getOrder(owner, order.Name)
		if getErr != nil {
			t.Fatalf("failed to reload order: %v", getErr)
		}
		if reloadedOrder.State != "Paid" {
			t.Fatalf("expected the buyer's own order to become \"Paid\", got %q", reloadedOrder.State)
		}
	})
}
