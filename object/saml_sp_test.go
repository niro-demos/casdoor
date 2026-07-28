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
	"testing"
)

// TestIsValidSamlRedirectURL_RejectsForgedHostOrigin reproduces TC-F837F217:
// the SAML ACS redirect-target check must never be satisfiable by anything
// the caller controls on an unauthenticated request. The prior implementation
// derived the trusted origin from the request's own Host header, so an
// attacker could set Host to their own domain and pass the check trivially.
// The fixed function no longer accepts a host argument at all, so this test
// asserts the invariant directly: the same attacker-controlled URL that
// exploited the bug must be rejected regardless of server config state.
func TestIsValidSamlRedirectURL_RejectsForgedHostOrigin(t *testing.T) {
	t.Setenv("origin", "")
	t.Setenv("originFrontend", "")

	redirectURL := "http://attacker.evil.example/collect"

	if IsValidSamlRedirectURL(redirectURL) {
		t.Fatalf("IsValidSamlRedirectURL(%q) = true; an attacker-controlled destination must never be trusted", redirectURL)
	}
}

// TestIsValidSamlRedirectURL_FailsClosedWhenOriginNotConfigured asserts that
// when this instance has not set `origin` / `originFrontend`, the endpoint
// fails closed (rejects every redirect) instead of falling back to any
// request-derived value.
func TestIsValidSamlRedirectURL_FailsClosedWhenOriginNotConfigured(t *testing.T) {
	t.Setenv("origin", "")
	t.Setenv("originFrontend", "")

	if IsValidSamlRedirectURL("https://door.casdoor.com/callback/saml") {
		t.Fatal("IsValidSamlRedirectURL must fail closed (reject) when neither origin nor originFrontend is configured")
	}
}

// TestIsValidSamlRedirectURL_AllowsConfiguredOrigin is the positive control:
// once this instance's own origin is configured, the legitimate SP-initiated
// redirect target (this instance's own /callback/saml page) must still be
// accepted.
func TestIsValidSamlRedirectURL_AllowsConfiguredOrigin(t *testing.T) {
	t.Setenv("origin", "https://door.casdoor.com")
	t.Setenv("originFrontend", "")

	legit := "https://door.casdoor.com/callback/saml"
	if !IsValidSamlRedirectURL(legit) {
		t.Fatalf("IsValidSamlRedirectURL(%q) = false; a redirect target matching the configured origin must be accepted", legit)
	}

	attacker := "https://attacker.evil.example/collect"
	if IsValidSamlRedirectURL(attacker) {
		t.Fatalf("IsValidSamlRedirectURL(%q) = true; a redirect target not matching the configured origin must be rejected", attacker)
	}
}

// TestIsValidSamlRedirectURL_AllowsConfiguredOriginFrontend covers
// split-deployment setups where the browser-facing origin
// (`originFrontend`) differs from the backend `origin`.
func TestIsValidSamlRedirectURL_AllowsConfiguredOriginFrontend(t *testing.T) {
	t.Setenv("origin", "https://api.casdoor.com")
	t.Setenv("originFrontend", "https://door.casdoor.com")

	legit := "https://door.casdoor.com/callback/saml"
	if !IsValidSamlRedirectURL(legit) {
		t.Fatalf("IsValidSamlRedirectURL(%q) = false; a redirect target matching the configured originFrontend must be accepted", legit)
	}
}
