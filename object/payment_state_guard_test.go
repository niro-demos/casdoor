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

	"github.com/casdoor/casdoor/pp"
)

// These tests pin the security invariant behind TC-176F99E4:
//
//   A customer must not be able to mark their own order or payment as paid, or
//   change its price, without completing a real payment through a payment
//   provider.
//
// The client-facing /api/update-order and /api/update-payment controllers run
// CheckOrderFieldChange / CheckPaymentFieldChange against the stored record
// before persisting. These unit tests exercise those guards directly (no DB),
// asserting the forbidden self-service transitions are rejected while benign
// updates and the trusted provider-driven transitions still pass through.

func TestCheckOrderFieldChange_RejectsClientPaidAndPriceMutation(t *testing.T) {
	// The stored order as created by /api/place-order: not yet paid.
	stored := &Order{
		Owner: "acme", Name: "order_1", User: "alice",
		State: "Created", Price: 5,
	}

	// ATTACK 1: client flips state -> Paid without any real payment. MUST be rejected.
	attackPaid := &Order{
		Owner: "acme", Name: "order_1", User: "alice",
		State: "Paid", Price: 5,
	}
	if err := CheckOrderFieldChange(stored, attackPaid); err == nil {
		t.Fatalf("INVARIANT VIOLATED: client self-marking order Created->Paid was allowed; " +
			"a customer can obtain paid goods for free")
	}

	// ATTACK 2: client changes the price. MUST be rejected.
	attackPrice := &Order{
		Owner: "acme", Name: "order_1", User: "alice",
		State: "Created", Price: 888888,
	}
	if err := CheckOrderFieldChange(stored, attackPrice); err == nil {
		t.Fatalf("INVARIANT VIOLATED: client changing order price was allowed; " +
			"a customer can forge the recorded amount")
	}

	// ATTACK 3: client flips to Paid AND inflates the price at once. MUST be rejected.
	attackBoth := &Order{
		Owner: "acme", Name: "order_1", User: "alice",
		State: "Paid", Price: 888888,
	}
	if err := CheckOrderFieldChange(stored, attackBoth); err == nil {
		t.Fatalf("INVARIANT VIOLATED: client self-marking order Paid with a forged price was allowed")
	}
}

func TestCheckOrderFieldChange_AllowsBenignAndProviderUpdates(t *testing.T) {
	stored := &Order{
		Owner: "acme", Name: "order_1", User: "alice",
		State: "Created", Price: 5,
	}

	// GREEN CONTROL: a benign self-service edit that touches neither price nor a
	// paid state must still be permitted, proving the guard is specific.
	benign := &Order{
		Owner: "acme", Name: "order_1", User: "alice",
		State: "Created", Price: 5, DisplayName: "Renamed order",
	}
	if err := CheckOrderFieldChange(stored, benign); err != nil {
		t.Fatalf("benign order update (no price/paid-state change) was wrongly rejected: %v", err)
	}

	// GREEN CONTROL: a non-paid state transition (e.g. cancellation) is still allowed.
	canceled := &Order{
		Owner: "acme", Name: "order_1", User: "alice",
		State: "Canceled", Price: 5,
	}
	if err := CheckOrderFieldChange(stored, canceled); err != nil {
		t.Fatalf("non-paid order state transition was wrongly rejected: %v", err)
	}
}

func TestCheckPaymentFieldChange_RejectsClientPaidAndPriceMutation(t *testing.T) {
	// The stored payment after /api/pay-order with the dummy provider: still Created.
	stored := &Payment{
		Owner: "acme", Name: "payment_1", User: "alice",
		State: pp.PaymentStateCreated, Price: 5,
	}

	// ATTACK 1: client flips state -> Paid without provider confirmation. MUST be rejected.
	attackPaid := &Payment{
		Owner: "acme", Name: "payment_1", User: "alice",
		State: pp.PaymentStatePaid, Price: 5,
	}
	if err := CheckPaymentFieldChange(stored, attackPaid); err == nil {
		t.Fatalf("INVARIANT VIOLATED: client self-marking payment Created->Paid was allowed; " +
			"a customer can forge a payment record")
	}

	// ATTACK 2: client changes the price. MUST be rejected.
	attackPrice := &Payment{
		Owner: "acme", Name: "payment_1", User: "alice",
		State: pp.PaymentStateCreated, Price: 9999,
	}
	if err := CheckPaymentFieldChange(stored, attackPrice); err == nil {
		t.Fatalf("INVARIANT VIOLATED: client changing payment price was allowed")
	}
}

func TestCheckPaymentFieldChange_AllowsBenignUpdates(t *testing.T) {
	stored := &Payment{
		Owner: "acme", Name: "payment_1", User: "alice",
		State: pp.PaymentStateCreated, Price: 5,
	}

	// GREEN CONTROL: benign invoice-detail edit with no price/paid-state change.
	benign := &Payment{
		Owner: "acme", Name: "payment_1", User: "alice",
		State: pp.PaymentStateCreated, Price: 5, InvoiceTitle: "Acme Inc.",
	}
	if err := CheckPaymentFieldChange(stored, benign); err != nil {
		t.Fatalf("benign payment update (no price/paid-state change) was wrongly rejected: %v", err)
	}
}
