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

func TestDummyPaymentProviderRejectsUnsignedNotify(t *testing.T) {
	provider, err := NewDummyPaymentProvider()
	if err != nil {
		t.Fatalf("NewDummyPaymentProvider() error = %v", err)
	}

	payResp, err := provider.Pay(&PayReq{
		Price:    10,
		Currency: "USD",
	})
	if err != nil {
		t.Fatalf("Pay() error = %v", err)
	}

	result, err := provider.Notify([]byte("{}"), payResp.OrderId)
	if err == nil {
		t.Fatalf("expected unsigned Dummy notification to be rejected, got result=%+v", result)
	}
	if result != nil && result.PaymentStatus == PaymentStatePaid {
		t.Fatalf("unsigned Dummy notification must not mark payment Paid: %+v", result)
	}
}

func TestDummyPaymentProviderAcceptsMatchingNotifyToken(t *testing.T) {
	provider, err := NewDummyPaymentProvider()
	if err != nil {
		t.Fatalf("NewDummyPaymentProvider() error = %v", err)
	}

	payResp, err := provider.Pay(&PayReq{
		Price:    10,
		Currency: "USD",
	})
	if err != nil {
		t.Fatalf("Pay() error = %v", err)
	}

	var orderInfo DummyOrderInfo
	if err := json.Unmarshal([]byte(payResp.OrderId), &orderInfo); err != nil {
		t.Fatalf("failed to decode dummy order info: %v", err)
	}
	if orderInfo.NotifyToken == "" {
		t.Fatal("expected dummy order info to include a notify token")
	}

	body, err := json.Marshal(DummyNotifyReq{NotifyToken: orderInfo.NotifyToken})
	if err != nil {
		t.Fatalf("failed to encode dummy notification: %v", err)
	}

	result, err := provider.Notify(body, payResp.OrderId)
	if err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if result.PaymentStatus != PaymentStatePaid {
		t.Fatalf("expected matching Dummy notification to mark payment Paid, got %+v", result)
	}
}
