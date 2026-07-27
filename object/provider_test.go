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

func TestGetMaskedProviderHidesPrivateProviderMaterial(t *testing.T) {
	provider := &Provider{
		Category:      "Email",
		ClientSecret:  "primary-secret",
		ClientSecret2: "secondary-secret",
		HttpHeaders: map[string]string{
			"Authorization": "Bearer header-secret",
		},
		Content:  "private-content",
		Metadata: "private-metadata",
		IdP:      "private-idp",
	}

	maskedProvider := GetMaskedProvider(provider, true)

	if maskedProvider.ClientSecret != "***" {
		t.Fatalf("expected clientSecret to be masked, got %q", maskedProvider.ClientSecret)
	}
	if maskedProvider.ClientSecret2 != "***" {
		t.Fatalf("expected clientSecret2 to be masked for email providers, got %q", maskedProvider.ClientSecret2)
	}
	if maskedProvider.HttpHeaders != nil {
		t.Fatalf("expected httpHeaders to be omitted from masked provider, got %#v", maskedProvider.HttpHeaders)
	}
	if maskedProvider.Content != "" {
		t.Fatalf("expected content to be omitted from masked provider, got %q", maskedProvider.Content)
	}
	if maskedProvider.Metadata != "" {
		t.Fatalf("expected metadata to be omitted from masked provider, got %q", maskedProvider.Metadata)
	}
	if maskedProvider.IdP != "" {
		t.Fatalf("expected idP to be omitted from masked provider, got %q", maskedProvider.IdP)
	}
}

func TestGetMaskedProviderKeepsPrivateProviderMaterialWhenMaskDisabled(t *testing.T) {
	provider := &Provider{
		Category:      "Email",
		ClientSecret:  "primary-secret",
		ClientSecret2: "secondary-secret",
		HttpHeaders: map[string]string{
			"Authorization": "Bearer header-secret",
		},
		Content:  "private-content",
		Metadata: "private-metadata",
		IdP:      "private-idp",
	}

	unmaskedProvider := GetMaskedProvider(provider, false)

	if unmaskedProvider.ClientSecret != "primary-secret" {
		t.Fatalf("expected clientSecret to be preserved, got %q", unmaskedProvider.ClientSecret)
	}
	if unmaskedProvider.ClientSecret2 != "secondary-secret" {
		t.Fatalf("expected clientSecret2 to be preserved, got %q", unmaskedProvider.ClientSecret2)
	}
	if unmaskedProvider.HttpHeaders["Authorization"] != "Bearer header-secret" {
		t.Fatalf("expected httpHeaders to be preserved, got %#v", unmaskedProvider.HttpHeaders)
	}
	if unmaskedProvider.Content != "private-content" {
		t.Fatalf("expected content to be preserved, got %q", unmaskedProvider.Content)
	}
	if unmaskedProvider.Metadata != "private-metadata" {
		t.Fatalf("expected metadata to be preserved, got %q", unmaskedProvider.Metadata)
	}
	if unmaskedProvider.IdP != "private-idp" {
		t.Fatalf("expected idP to be preserved, got %q", unmaskedProvider.IdP)
	}
}
