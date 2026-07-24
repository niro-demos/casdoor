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

package pp

import (
	"encoding/json"
	"testing"
)

// Security invariant (TC-70EEE265):
//
//	An anonymous, unauthenticated caller must NOT be able to declare a payment as
//	successfully Paid. Only a caller that can prove it came from the configured
//	payment provider (here: holds the provider's shared secret) may transition a
//	payment to Paid.
//
// The /api/notify-payment endpoint is anonymous by design (real provider webhooks
// arrive unauthenticated), so authenticity is delegated to the provider's
// Notify(). Before the fix, DummyPaymentProvider.Notify returned PaymentStatePaid
// unconditionally for ANY body, letting an anonymous caller mark any tenant's
// payment as paid. These tests assert Notify now rejects unauthenticated
// callbacks and only accepts a correctly-signed one.

// orderId as produced by DummyPaymentProvider.Pay for a $5 product.
const testDummyOrderId = `{"price":5,"currency":"USD","productDisplayName":""}`

const testDummySecret = "provider-shared-secret"

// TestDummyNotifyRejectsAnonymousForgery is the core regression test: the exact
// anonymous forgery the PoC performed — an empty JSON body with no signature —
// must NOT yield a Paid result.
func TestDummyNotifyRejectsAnonymousForgery(t *testing.T) {
	provider, err := NewDummyPaymentProvider(testDummySecret)
	if err != nil {
		t.Fatalf("NewDummyPaymentProvider: %v", err)
	}

	// This is the smoking-gun request from the finding: fully anonymous, empty
	// body, no signature.
	res, err := provider.Notify([]byte(`{}`), testDummyOrderId)
	if err == nil && res != nil && res.PaymentStatus == PaymentStatePaid {
		t.Fatalf("INVARIANT VIOLATED: anonymous notify with body `{}` (no signature) "+
			"marked the payment as Paid (%q); any caller who knows a tenant's "+
			"owner+payment name could obtain paid products for free", res.PaymentStatus)
	}
	if res != nil && res.PaymentStatus == PaymentStatePaid {
		t.Fatalf("INVARIANT VIOLATED: anonymous notify returned Paid despite error %v", err)
	}
}

// TestDummyNotifyRejectsWrongSignature ensures a caller who does not hold the
// provider's secret cannot forge a valid callback even if it supplies some
// signature.
func TestDummyNotifyRejectsWrongSignature(t *testing.T) {
	provider, err := NewDummyPaymentProvider(testDummySecret)
	if err != nil {
		t.Fatalf("NewDummyPaymentProvider: %v", err)
	}

	body, _ := json.Marshal(DummyNotifyBody{Signature: "not-the-real-signature"})
	res, err := provider.Notify(body, testDummyOrderId)
	if err == nil && res != nil && res.PaymentStatus == PaymentStatePaid {
		t.Fatalf("INVARIANT VIOLATED: notify with a forged signature was accepted as Paid")
	}
}

// TestDummyNotifyAcceptsValidSignature is the paired legitimate case: the real
// provider webhook, which holds the shared secret, still succeeds. This proves
// the rejection above is specific to unauthenticated callers, not a broken
// provider.
func TestDummyNotifyAcceptsValidSignature(t *testing.T) {
	provider, err := NewDummyPaymentProvider(testDummySecret)
	if err != nil {
		t.Fatalf("NewDummyPaymentProvider: %v", err)
	}

	sig := signOrderId(testDummySecret, testDummyOrderId)
	body, _ := json.Marshal(DummyNotifyBody{Signature: sig})
	res, err := provider.Notify(body, testDummyOrderId)
	if err != nil {
		t.Fatalf("legitimate signed notify should succeed, got error: %v", err)
	}
	if res == nil || res.PaymentStatus != PaymentStatePaid {
		t.Fatalf("legitimate signed notify should be Paid, got %+v", res)
	}
	if res.Price != 5 || res.Currency != "USD" {
		t.Fatalf("legitimate notify lost order info: got price=%v currency=%q", res.Price, res.Currency)
	}
}
