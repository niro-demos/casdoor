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
	"strings"
	"testing"
)

func TestGenerateSamlRequestReturnsControlledErrorForUnknownProvider(t *testing.T) {
	setupSamlRequestTestAdapter(t)

	_, _, err := GenerateSamlRequest("admin/oauth-provider", "https://example.com/callback", "example.com", "en")
	if err == nil {
		t.Fatal("GenerateSamlRequest() for an existing non-SAML provider returned nil error")
	}
	if !strings.Contains(err.Error(), "category is not SAML") {
		t.Fatalf("GenerateSamlRequest() for an existing non-SAML provider error = %q, want category error", err.Error())
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GenerateSamlRequest() panicked for an unknown provider: %v", r)
		}
	}()

	_, _, err = GenerateSamlRequest("admin/nonexistent", "https://evil.example", "example.com", "en")
	if err == nil {
		t.Fatal("GenerateSamlRequest() for an unknown provider returned nil error")
	}
	if strings.Contains(err.Error(), "runtime error") || strings.Contains(err.Error(), "nil pointer") {
		t.Fatalf("GenerateSamlRequest() for an unknown provider returned panic details: %q", err.Error())
	}
}

func setupSamlRequestTestAdapter(t *testing.T) {
	t.Helper()

	previousOrmer := ormer
	adapter, err := NewAdapter("sqlite", "file::memory:?cache=shared", "")
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}
	ormer = adapter
	t.Cleanup(func() {
		ormer = previousOrmer
		adapter.close()
	})

	if err = ormer.Engine.Sync2(new(Provider)); err != nil {
		t.Fatalf("Sync2(Provider) error = %v", err)
	}

	provider := &Provider{
		Owner:    "admin",
		Name:     "oauth-provider",
		Category: "OAuth",
	}
	if _, err = ormer.Engine.Insert(provider); err != nil {
		t.Fatalf("Insert(Provider) error = %v", err)
	}
}
