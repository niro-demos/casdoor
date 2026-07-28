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
	"strings"
	"testing"

	"github.com/casdoor/casdoor/util"
)

// TestGenerateSamlRequestUnknownProviderReturnsCleanError guards the
// invariant behind TC-F5A8E277: GenerateSamlRequest() must return a clean
// error for an unknown provider id instead of panicking with a nil pointer
// dereference on provider.Category. GetProvider(id) returns (nil, nil) when
// no row matches, and the caller (controllers.ApiController.GetSamlLogin,
// reachable unauthenticated at GET /api/get-saml-login) only turns a
// returned error into a clean JSON response - it never recovers a panic.
func TestGenerateSamlRequestUnknownProviderReturnsCleanError(t *testing.T) {
	InitConfig()

	unknownId := "admin/nonexistent-provider-" + util.GenerateId()

	auth, method, err := GenerateSamlRequest(unknownId, "", "localhost:8000", "en")

	if err == nil {
		t.Fatalf("expected GenerateSamlRequest to return a clean error for unknown provider id %q, got nil error (auth=%q, method=%q)", unknownId, auth, method)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected a clean 'does not exist' error for unknown provider id %q, got: %v", unknownId, err)
	}
}

// TestGenerateSamlRequestExistingNonSamlProviderReturnsCleanError is the
// positive control: an existing, non-SAML provider must also produce a
// clean error (wrong category), proving the handler itself is healthy and
// that the panic is specific to the "provider not found" path.
func TestGenerateSamlRequestExistingNonSamlProviderReturnsCleanError(t *testing.T) {
	InitConfig()

	provider := &Provider{
		Owner:    "admin",
		Name:     "provider_saml_sp_test_non_saml_" + util.GenerateId(),
		Category: "Email",
		Type:     "Default",
	}
	_, err := AddProvider(provider)
	if err != nil {
		t.Fatalf("failed to seed non-SAML provider fixture: %v", err)
	}
	defer func() {
		_, _ = DeleteProvider(provider)
	}()

	auth, method, err := GenerateSamlRequest(provider.GetId(), "", "localhost:8000", "en")

	if err == nil {
		t.Fatalf("expected GenerateSamlRequest to return a clean error for a non-SAML provider, got nil error (auth=%q, method=%q)", auth, method)
	}
}
