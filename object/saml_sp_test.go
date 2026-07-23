// Copyright 2024 The Casdoor Authors. All Rights Reserved.
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

// TestValidateSamlProvider_NilProviderReturnsError is the regression test for
// TC-603B4350: an unauthenticated GET /api/get-saml-login with a well-formed but
// nonexistent provider id (e.g. "admin/nonexistent-provider") reaches
// GenerateSamlRequest -> validateSamlProvider with a nil provider, because
// GetProvider returns (nil, nil) for an owner/name id whose row does not exist.
//
// Invariant: a nil (not-found) provider MUST yield a clean, non-nil error — never
// a nil-pointer dereference that panics the request goroutine and lets beego's
// debug renderer leak internal source paths, the panic location, and the
// framework/runtime version banner to an unauthenticated caller.
//
// On the unfixed code, validateSamlProvider dereferences provider.Category with
// no nil guard, so this test panics (RED). With the nil check in place it returns
// a clean error (GREEN).
func TestValidateSamlProvider_NilProviderReturnsError(t *testing.T) {
	const id = "admin/nonexistent-provider"

	err := validateSamlProvider(nil, id, "en")
	if err == nil {
		t.Fatalf("validateSamlProvider(nil, %q) returned nil error; expected a clean not-found error, not a nil-pointer dereference", id)
	}
	if !strings.Contains(err.Error(), id) {
		t.Errorf("error %q does not mention the provider id %q; caller should be told which provider was not found", err.Error(), id)
	}
}

// TestValidateSamlProvider_Control is the paired green baseline (positive
// control): a real, well-formed SAML provider must validate with no error. This
// proves the RED above is specifically the nil/not-found invariant, not a broken
// test setup that rejects everything.
func TestValidateSamlProvider_Control(t *testing.T) {
	provider := &Provider{Owner: "admin", Name: "saml-ok", Category: "SAML"}
	if err := validateSamlProvider(provider, provider.GetId(), "en"); err != nil {
		t.Fatalf("validateSamlProvider on a valid SAML provider returned error %q; a legitimate provider must validate cleanly", err.Error())
	}
}

// TestValidateSamlProvider_NonSamlCategory guards the adjacent invariant: an
// existing provider whose Category is not "SAML" must also produce a clean error
// (this path already worked; the test locks it in alongside the nil fix).
func TestValidateSamlProvider_NonSamlCategory(t *testing.T) {
	provider := &Provider{Owner: "admin", Name: "oauth-provider", Category: "OAuth"}
	if err := validateSamlProvider(provider, provider.GetId(), "en"); err == nil {
		t.Fatalf("validateSamlProvider on a non-SAML provider returned nil error; a non-SAML category must be rejected cleanly")
	}
}
