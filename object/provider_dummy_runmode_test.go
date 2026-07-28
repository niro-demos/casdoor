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
	"testing"

	"github.com/casdoor/casdoor/pp"
)

// These tests express the invariant from TC-37061445: the built-in `Dummy`
// payment provider self-confirms every payment as `Paid` without ever talking
// to a real payment gateway (see pp/dummy.go Notify()). It must never be
// resolvable into a usable payment engine, nor attachable to a product's
// active provider list, when Casdoor is running in production (`runmode =
// prod`). It must keep working in non-prod runmodes so local dev/test/CI
// checkout flows are unaffected.

func TestGetPaymentProviderRejectsDummyInProdRunmode(t *testing.T) {
	dummyProvider := &Provider{
		Owner: "niro-test",
		Name:  "vec-dummy",
		Type:  "Dummy",
	}

	t.Run("runmode=prod must reject the Dummy provider", func(t *testing.T) {
		t.Setenv("runmode", "prod")

		pProvider, err := GetPaymentProvider(dummyProvider)
		if err == nil {
			t.Fatalf("expected GetPaymentProvider to reject a Dummy provider under runmode=prod, got provider: %#v", pProvider)
		}
		if pProvider != nil {
			t.Fatalf("expected a nil payment provider when rejected, got: %#v", pProvider)
		}
	})

	t.Run("runmode=dev keeps the Dummy provider usable for legitimate local/test checkout", func(t *testing.T) {
		t.Setenv("runmode", "dev")

		pProvider, err := GetPaymentProvider(dummyProvider)
		if err != nil {
			t.Fatalf("expected GetPaymentProvider to succeed for a Dummy provider under runmode=dev, got error: %v", err)
		}
		if _, ok := pProvider.(*pp.DummyPaymentProvider); !ok {
			t.Fatalf("expected a *pp.DummyPaymentProvider, got: %#v", pProvider)
		}
	})
}

func TestIsValidProviderRejectsDummyInProdRunmode(t *testing.T) {
	dummyProvider := &Provider{Owner: "niro-test", Name: "vec-dummy", Type: "Dummy"}
	product := &Product{
		Owner:     "niro-test",
		Name:      "vec-widget",
		Currency:  "USD",
		State:     "Published",
		Providers: []string{"vec-dummy"},
	}

	t.Run("runmode=prod must reject attaching/using Dummy on a real product", func(t *testing.T) {
		t.Setenv("runmode", "prod")

		if err := product.isValidProvider(dummyProvider); err == nil {
			t.Fatalf("expected isValidProvider to reject a Dummy provider under runmode=prod")
		}
	})

	t.Run("runmode=dev keeps Dummy usable for legitimate testing", func(t *testing.T) {
		t.Setenv("runmode", "dev")

		if err := product.isValidProvider(dummyProvider); err != nil {
			t.Fatalf("expected isValidProvider to accept a Dummy provider under runmode=dev, got: %v", err)
		}
	})

	t.Run("a real provider type stays valid regardless of runmode (control)", func(t *testing.T) {
		realProvider := &Provider{Owner: "niro-test", Name: "vec-stripe", Type: "Stripe"}
		realProduct := &Product{
			Owner:     "niro-test",
			Name:      "vec-widget",
			Currency:  "USD",
			State:     "Published",
			Providers: []string{"vec-stripe"},
		}

		t.Setenv("runmode", "prod")
		if err := realProduct.isValidProvider(realProvider); err != nil {
			t.Fatalf("expected a real (non-Dummy) provider to remain valid under runmode=prod, got: %v", err)
		}

		t.Setenv("runmode", "dev")
		if err := realProduct.isValidProvider(realProvider); err != nil {
			t.Fatalf("expected a real (non-Dummy) provider to remain valid under runmode=dev, got: %v", err)
		}
	})
}
