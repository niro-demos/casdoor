// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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

import "testing"

// TestSanitizeProviderForPublicProductRedactsCredentials is the regression
// test for TC-5B136301: an anonymous, unauthenticated caller of
// GET /api/get-product (authz/authz.go whitelists this route for "*",
// which is intentional so products are browsable pre-login) must never
// receive a linked payment provider's raw cert/clientId/clientId2/appId —
// only clientSecret/clientSecret2 were being masked before this fix.
//
// ExtendProductWithProviders (the function GetProduct calls, see
// controllers/product.go) builds product.ProviderObjs by running every
// attached provider through sanitizeProviderForPublicProduct. This test
// exercises that function directly, without a live DB, using a provider
// shaped like the Stripe/Alipay-style payment providers Products actually
// reference (Product.Providers is only ever populated from Plan.PaymentProviders,
// see CreateProductForPlan).
func TestSanitizeProviderForPublicProductRedactsCredentials(t *testing.T) {
	const (
		certValue          = "-----BEGIN CERTIFICATE-----\nNIROTESTCERTDATA\n-----END CERTIFICATE-----"
		clientIdValue      = "pk_live_NIRO_TEST_51ABC123XYZ"
		clientSecretValue  = "sk_live_NIRO_TEST_SUPERSECRETVALUE987654321"
		clientId2Value     = "id2_NIRO_TEST"
		clientSecret2Value = "sk2_live_NIRO_TEST_ANOTHERSECRET"
		appIdValue         = "acct_NIROTEST1234567890"
	)

	provider := &Provider{
		Owner:         "acme",
		Name:          "provider_stripe_niro_test",
		DisplayName:   "Stripe (Niro test)",
		Category:      "Payment",
		Type:          "Stripe",
		ClientId:      clientIdValue,
		ClientSecret:  clientSecretValue,
		ClientId2:     clientId2Value,
		ClientSecret2: clientSecret2Value,
		Cert:          certValue,
		AppId:         appIdValue,
	}

	sanitized := sanitizeProviderForPublicProduct(provider)

	// The invariant: internal payment provider configuration (API keys,
	// client secrets, certificates) must not be exposed to anonymous,
	// unauthenticated visitors browsing a product's payment options.
	credentialFields := map[string]string{
		"cert":      sanitized.Cert,
		"clientId":  sanitized.ClientId,
		"clientId2": sanitized.ClientId2,
		"appId":     sanitized.AppId,
	}
	for field, got := range credentialFields {
		if got != "" && got != "***" {
			t.Errorf("sanitizeProviderForPublicProduct leaked %s = %q, want empty or masked", field, got)
		}
	}

	// Positive control: the fields a public storefront actually needs to
	// render a payment option (name/type/displayName/category) must survive
	// sanitization untouched — proving this isn't a broken/blanket wipe of
	// the provider, just the credential fields.
	if sanitized.Name != provider.Name {
		t.Errorf("Name = %q, want %q (display fields must not be stripped)", sanitized.Name, provider.Name)
	}
	if sanitized.Type != "Stripe" {
		t.Errorf("Type = %q, want %q (display fields must not be stripped)", sanitized.Type, "Stripe")
	}
	if sanitized.DisplayName != provider.DisplayName {
		t.Errorf("DisplayName = %q, want %q (display fields must not be stripped)", sanitized.DisplayName, provider.DisplayName)
	}
	if sanitized.Category != "Payment" {
		t.Errorf("Category = %q, want %q (display fields must not be stripped)", sanitized.Category, "Payment")
	}
}

//func TestProduct(t *testing.T) {
//	InitConfig()
//
//	product, _ := GetProduct("admin/product_123")
//	provider, _ := getProvider(product.Owner, "provider_pay_alipay")
//	cert, _ := getCert(product.Owner, "cert-pay-alipay")
//	pProvider, err := pp.GetPaymentProvider(provider.Type, provider.ClientId, provider.ClientSecret, provider.Host, cert.Certificate, cert.PrivateKey, cert.AuthorityPublicKey, cert.AuthorityRootPublicKey, provider.ClientId2)
//	if err != nil {
//		panic(err)
//	}
//
//	paymentName := util.GenerateTimeId()
//	returnUrl := ""
//	notifyUrl := ""
//	payUrl, _, err := pProvider.Pay(provider.Name, product.Name, "alice", paymentName, product.DisplayName, product.Price, product.Currency, returnUrl, notifyUrl)
//	if err != nil {
//		panic(err)
//	}
//
//	println(payUrl)
//}
