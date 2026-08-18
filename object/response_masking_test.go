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

import "testing"

func TestGetMaskedApplicationMasksOrganizationAuthenticationKeys(t *testing.T) {
	const (
		obfuscatorKey  = "password-obfuscator-key"
		kerberosKeytab = "base64-encoded-keytab"
	)

	publicApplication := &Application{OrganizationObj: &Organization{
		PasswordObfuscatorKey: obfuscatorKey,
		KerberosKeytab:        kerberosKeytab,
	}}
	masked := GetMaskedApplication(publicApplication, "")
	if got := masked.OrganizationObj.PasswordObfuscatorKey; got != "***" {
		t.Errorf("PasswordObfuscatorKey = %q, want masked value", got)
	}
	if got := masked.OrganizationObj.KerberosKeytab; got != "***" {
		t.Errorf("KerberosKeytab = %q, want masked value", got)
	}

	adminApplication := &Application{OrganizationObj: &Organization{
		PasswordObfuscatorKey: obfuscatorKey,
		KerberosKeytab:        kerberosKeytab,
	}}
	unmasked := GetMaskedApplication(adminApplication, "built-in/admin")
	if got := unmasked.OrganizationObj.PasswordObfuscatorKey; got != obfuscatorKey {
		t.Errorf("global administrator PasswordObfuscatorKey = %q, want original value", got)
	}
	if got := unmasked.OrganizationObj.KerberosKeytab; got != kerberosKeytab {
		t.Errorf("global administrator KerberosKeytab = %q, want original value", got)
	}
}

func TestGetMaskedOrganizationMasksAuthenticationKeysForNonAdmins(t *testing.T) {
	const (
		obfuscatorKey  = "password-obfuscator-key"
		kerberosKeytab = "base64-encoded-keytab"
	)

	masked, err := GetMaskedOrganization(false, &Organization{
		PasswordObfuscatorKey: obfuscatorKey,
		KerberosKeytab:        kerberosKeytab,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := masked.PasswordObfuscatorKey; got != "***" {
		t.Errorf("PasswordObfuscatorKey = %q, want masked value", got)
	}
	if got := masked.KerberosKeytab; got != "***" {
		t.Errorf("KerberosKeytab = %q, want masked value", got)
	}

	unmasked, err := GetMaskedOrganization(true, &Organization{
		PasswordObfuscatorKey: obfuscatorKey,
		KerberosKeytab:        kerberosKeytab,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := unmasked.PasswordObfuscatorKey; got != obfuscatorKey {
		t.Errorf("administrator PasswordObfuscatorKey = %q, want original value", got)
	}
	if got := unmasked.KerberosKeytab; got != kerberosKeytab {
		t.Errorf("administrator KerberosKeytab = %q, want original value", got)
	}
}

func TestGetMaskedProviderMasksCredentialHeadersWithoutMutatingProvider(t *testing.T) {
	provider := &Provider{
		ClientSecret:  "client-secret",
		ClientSecret2: "secondary-client-secret",
		HttpHeaders: map[string]string{
			"Authorization":       "Bearer authorization-secret",
			"Proxy-Authorization": "Basic proxy-secret",
			"X-Api-Key":           "api-key",
			"X-Access-Token":      "access-token",
			"X-Client-Secret":     "header-secret",
			"X-Credential":        "credential",
			"X-Nonsecret":         "visible",
		},
	}

	masked := GetMaskedProvider(provider, true)
	if masked == provider {
		t.Fatal("masked provider aliases the stored provider")
	}
	if masked.ClientSecret != "***" || masked.ClientSecret2 != "***" {
		t.Errorf("dedicated client secrets were not masked: %q, %q", masked.ClientSecret, masked.ClientSecret2)
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "X-Access-Token", "X-Client-Secret", "X-Credential"} {
		if got := masked.HttpHeaders[name]; got != "***" {
			t.Errorf("header %q = %q, want masked value", name, got)
		}
	}
	if got := masked.HttpHeaders["X-Nonsecret"]; got != "visible" {
		t.Errorf("non-secret header = %q, want preserved value", got)
	}
	if got := provider.ClientSecret; got != "client-secret" {
		t.Errorf("stored ClientSecret was mutated to %q", got)
	}
	if got := provider.HttpHeaders["Authorization"]; got != "Bearer authorization-secret" {
		t.Errorf("stored Authorization header was mutated to %q", got)
	}
}
