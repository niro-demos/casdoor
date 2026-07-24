// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type DummyPaymentProvider struct {
	// ClientSecret is a shared secret used to authenticate notify callbacks.
	// The Dummy provider is a test/mock provider; requiring a signature keeps an
	// anonymous caller from forging a "Paid" transition (see Notify).
	ClientSecret string
}

type DummyOrderInfo struct {
	Price              float64 `json:"price"`
	Currency           string  `json:"currency"`
	ProductDisplayName string  `json:"productDisplayName"`
}

// DummyNotifyBody is the expected shape of a Dummy provider notify callback.
// The signature is an HMAC-SHA256 (hex) of the OrderId keyed by ClientSecret,
// so only a caller that holds the configured shared secret can prove the
// callback is authentic.
type DummyNotifyBody struct {
	Signature string `json:"signature"`
}

func NewDummyPaymentProvider(clientSecret string) (*DummyPaymentProvider, error) {
	pp := &DummyPaymentProvider{ClientSecret: clientSecret}
	return pp, nil
}

// signOrderId computes the expected notify signature for an orderId.
func signOrderId(secret string, orderId string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(orderId))
	return hex.EncodeToString(mac.Sum(nil))
}

func (pp *DummyPaymentProvider) Pay(r *PayReq) (*PayResp, error) {
	// Encode payment information in OrderId for later retrieval in Notify.
	// Note: This is a test/mock provider and the OrderId is only used internally for testing.
	// Real payment providers would receive this information from their external payment gateway.
	orderInfo := DummyOrderInfo{
		Price:              r.Price,
		Currency:           r.Currency,
		ProductDisplayName: "",
	}
	orderInfoBytes, err := json.Marshal(orderInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode order info: %w", err)
	}

	return &PayResp{
		PayUrl:  r.ReturnUrl,
		OrderId: string(orderInfoBytes),
	}, nil
}

func (pp *DummyPaymentProvider) Notify(body []byte, orderId string) (*NotifyResult, error) {
	// Authenticate the callback. The /api/notify-payment endpoint is anonymous by
	// design (real provider webhooks arrive unauthenticated), so authenticity is
	// delegated to the provider here. Without a shared secret the Dummy provider
	// would accept ANY body and unconditionally mint a "Paid" transaction, letting
	// an anonymous caller mark any tenant's payment as paid. Require an
	// HMAC-SHA256 signature over the orderId keyed by the provider's ClientSecret,
	// mirroring the signature checks in stripe.go / alipay.go.
	if pp.ClientSecret == "" {
		return nil, fmt.Errorf("dummy payment provider is not configured with a client secret; refusing to confirm payment")
	}

	var notifyBody DummyNotifyBody
	if err := json.Unmarshal(body, &notifyBody); err != nil {
		return nil, fmt.Errorf("failed to decode notify body: %w", err)
	}

	expected := signOrderId(pp.ClientSecret, orderId)
	if notifyBody.Signature == "" || !hmac.Equal([]byte(notifyBody.Signature), []byte(expected)) {
		return nil, fmt.Errorf("invalid or missing payment notification signature")
	}

	// Decode payment information from OrderId
	var orderInfo DummyOrderInfo
	if orderId != "" {
		err := json.Unmarshal([]byte(orderId), &orderInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to decode order info: %w", err)
		}
	}

	return &NotifyResult{
		PaymentStatus:      PaymentStatePaid,
		Price:              orderInfo.Price,
		Currency:           orderInfo.Currency,
		ProductDisplayName: orderInfo.ProductDisplayName,
	}, nil
}

func (pp *DummyPaymentProvider) GetInvoice(paymentName string, personName string, personIdCard string, personEmail string, personPhone string, invoiceType string, invoiceTitle string, invoiceTaxId string) (string, error) {
	return "", nil
}

func (pp *DummyPaymentProvider) GetResponseError(err error) string {
	return ""
}
