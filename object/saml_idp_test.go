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
	"encoding/base64"
	"testing"
)

// buildSamlAuthnRequestXML builds a minimal <samlp:AuthnRequest> with the
// given Issuer and AssertionConsumerServiceURL, mirroring the shape an
// external SAML SP (or an attacker) would send to /api/login.
func buildSamlAuthnRequestXML(issuer, acsURL string) string {
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test123" Version="2.0" IssueInstant="2026-08-17T00:00:00Z" AssertionConsumerServiceURL="` + acsURL + `" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>` + issuer + `</saml:Issuer></samlp:AuthnRequest>`
}

// TestGetSamlResponseRejectsUnregisteredAssertionConsumerServiceURL asserts
// the invariant behind TC-EC453F9A: when an application has no SamlReplyUrl
// configured, GetSamlResponse must only deliver the signed SAML assertion to
// an AssertionConsumerServiceURL the application actually registered in
// RedirectUris - never to an arbitrary URL supplied by the incoming request.
func TestGetSamlResponseRejectsUnregisteredAssertionConsumerServiceURL(t *testing.T) {
	InitConfig()

	// Use the seeded built-in admin user (present in every Casdoor install)
	// so ExtendUserWithRolesAndPermissions() can resolve it; the finding
	// itself was demonstrated against this same account.
	user, err := GetUser("built-in/admin")
	if err != nil {
		t.Fatalf("failed to load built-in/admin test user: %v", err)
	}
	if user == nil {
		t.Fatal("built-in/admin test user not found; expected the seeded built-in admin account to exist")
	}

	attackerACS := "https://attacker.example.com/acs-collect"
	legitimateACS := "https://sp.example.com/acs"

	application := &Application{
		Owner:        "admin",
		Name:         "saml-acs-test-app",
		DisplayName:  "saml-acs-test-app",
		RedirectUris: []string{legitimateACS},
		// SamlReplyUrl is intentionally left empty: this is exactly the
		// configuration state the finding exploited (no server-side value
		// to fall back on, so the request-supplied ACS URL must be checked
		// against RedirectUris instead of being trusted verbatim).
	}

	// The Issuer uses the http://localhost:* bypass in util.IsValidOrigin so
	// only the ACS URL itself is under test here, matching the finding's PoC.
	attackerIssuer := "http://localhost:9999/evil-sp"

	// --- Attack case: unregistered ACS URL must be rejected -----------------
	maliciousXML := buildSamlAuthnRequestXML(attackerIssuer, attackerACS)
	maliciousB64 := base64.StdEncoding.EncodeToString([]byte(maliciousXML))

	_, _, _, err = GetSamlResponse(application, user, maliciousB64, "localhost:8000")
	if err == nil {
		t.Fatalf("expected GetSamlResponse to reject an AssertionConsumerServiceURL not present in application.RedirectUris, but it succeeded")
	}

	// --- Control case: registered ACS URL must still be honored -------------
	legitimateXML := buildSamlAuthnRequestXML(attackerIssuer, legitimateACS)
	legitimateB64 := base64.StdEncoding.EncodeToString([]byte(legitimateXML))

	_, redirectUrl, _, err := GetSamlResponse(application, user, legitimateB64, "localhost:8000")
	if err != nil {
		t.Fatalf("expected GetSamlResponse to accept an AssertionConsumerServiceURL present in application.RedirectUris, got error: %v", err)
	}
	if redirectUrl != legitimateACS {
		t.Fatalf("expected redirect URL %q, got %q", legitimateACS, redirectUrl)
	}
}
