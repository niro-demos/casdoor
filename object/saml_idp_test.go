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
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setUpSamlTestOrmer points the package-level `ormer` at a throwaway, isolated
// sqlite database for the duration of the test (restored on cleanup), and
// seeds the single Cert row GetSamlResponse() needs to sign a response. This
// mirrors how the project's own harness runs Casdoor against sqlite
// (niro/harness/start.sh) rather than requiring a live MySQL instance.
func setUpSamlTestOrmer(t *testing.T) {
	t.Helper()

	dbFile := filepath.Join(t.TempDir(), "saml_idp_test.db")
	adapter, err := NewAdapter("sqlite", fmt.Sprintf("file:%s?cache=shared", dbFile), "casdoor")
	if err != nil {
		t.Fatalf("failed to open isolated sqlite db for test: %v", err)
	}

	prevOrmer := ormer
	ormer = adapter
	t.Cleanup(func() {
		ormer = prevOrmer
	})

	ormer.createTable()

	added, err := AddCert(&Cert{
		Owner:           "admin",
		Name:            "cert-built-in",
		DisplayName:     "Test built-in cert",
		Scope:           "signing",
		Type:            "x509",
		CryptoAlgorithm: "RS256",
		BitSize:         2048,
		ExpireInYears:   10,
	})
	if err != nil {
		t.Fatalf("failed to seed test cert: %v", err)
	}
	if !added {
		t.Fatalf("test cert was not inserted")
	}
}

// samlTestAuthnRequest builds a raw (non-DEFLATEd) AuthnRequest containing the
// literal substring "xmlns:" -- the same heuristic object/saml_idp.go
// GetSamlResponse() uses to skip DEFLATE decompression -- with the given
// Issuer and AssertionConsumerServiceURL, base64-encoded the way the
// /api/login endpoint expects `samlRequest`. This is a direct translation of
// TC-3128DF84's poc.go buildAuthnRequest().
func samlTestAuthnRequest(id, issuer, acsURL string) string {
	xmlStr := fmt.Sprintf(
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0" IssueInstant="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="%s"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		id, time.Now().UTC().Format(time.RFC3339), acsURL, issuer,
	)
	return base64.StdEncoding.EncodeToString([]byte(xmlStr))
}

type samlTestResponse struct {
	XMLName     xml.Name `xml:"Response"`
	Destination string   `xml:"Destination,attr"`
	Assertion   struct {
		Subject struct {
			NameID              string `xml:"NameID"`
			SubjectConfirmation struct {
				SubjectConfirmationData struct {
					Recipient string `xml:"Recipient,attr"`
				} `xml:"SubjectConfirmationData"`
			} `xml:"SubjectConfirmation"`
		} `xml:"Subject"`
	} `xml:"Assertion"`
}

// samlTestUniqueID returns a short unique-enough suffix for AuthnRequest IDs
// across sub-tests.
func samlTestUniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// TestGetSamlResponseRejectsUnregisteredAssertionConsumerServiceURL is the
// regression test for TC-3128DF84: when an application has no SamlReplyUrl
// configured (the default), GetSamlResponse() must not deliver a signed SAML
// identity assertion to an attacker-supplied, unregistered
// AssertionConsumerServiceURL taken verbatim from the unauthenticated
// incoming AuthnRequest.
//
// Invariant under test: the signed SAML identity assertion produced during
// SAML SSO login must only be delivered to a pre-registered, trusted
// relying-party callback address for that application.
func TestGetSamlResponseRejectsUnregisteredAssertionConsumerServiceURL(t *testing.T) {
	setUpSamlTestOrmer(t)

	const registeredRedirectUri = "http://localhost:8000/callback"
	application := &Application{
		Owner:                 "admin",
		Name:                  "app-acme",
		Organization:          "acme",
		RedirectUris:          []string{registeredRedirectUri},
		SamlReplyUrl:          "", // default: no dedicated SAML reply URL configured
		DisableSamlAttributes: true,
	}
	user := &User{
		Owner:       "acme",
		Name:        "alice",
		DisplayName: "Alice Standard (Acme)",
		Email:       "alice@acme.example.com",
	}
	host := "http://localhost:8000"

	// --- Positive control: the ACS URL is the application's own registered
	// redirect URI. This must succeed and the resulting assertion must be
	// scoped to that trusted URL -- proving the test environment and the
	// legitimate SAML SSO flow are healthy. ---
	t.Run("registered ACS URL is accepted and scoped correctly", func(t *testing.T) {
		samlRequest := samlTestAuthnRequest("legit-"+samlTestUniqueID(), registeredRedirectUri, registeredRedirectUri)

		data, redirectUrl, _, err := GetSamlResponse(application, user, samlRequest, host)
		if err != nil {
			t.Fatalf("legitimate request was rejected, environment is broken: %v", err)
		}
		if redirectUrl != registeredRedirectUri {
			t.Fatalf("redirectUrl = %q, want %q", redirectUrl, registeredRedirectUri)
		}

		xmlBytes, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			t.Fatalf("failed to decode signed assertion: %v", err)
		}
		var parsed samlTestResponse
		if err := xml.Unmarshal(xmlBytes, &parsed); err != nil {
			t.Fatalf("failed to parse signed SAML response: %v", err)
		}
		if parsed.Destination != registeredRedirectUri {
			t.Fatalf("Response/@Destination = %q, want %q", parsed.Destination, registeredRedirectUri)
		}
		if parsed.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != registeredRedirectUri {
			t.Fatalf("SubjectConfirmationData/@Recipient = %q, want %q", parsed.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient, registeredRedirectUri)
		}
	})

	// --- Attack case: the ACS URL is an attacker-controlled, unregistered
	// URL. The invariant requires this be rejected outright -- never signed,
	// never delivered. Reproduced with two different attacker URLs to match
	// the finding's determinism check. ---
	attackerURLs := []string{
		"http://evil.attacker.example/collect",
		"https://phish.badguy.test/steal-saml",
	}
	for _, attackerURL := range attackerURLs {
		attackerURL := attackerURL
		t.Run("attacker-controlled ACS URL "+attackerURL+" is rejected", func(t *testing.T) {
			samlRequest := samlTestAuthnRequest("attack-"+samlTestUniqueID(), registeredRedirectUri, attackerURL)

			data, redirectUrl, _, err := GetSamlResponse(application, user, samlRequest, host)
			if err == nil {
				t.Fatalf("VULNERABLE: server accepted an unregistered AssertionConsumerServiceURL and signed an assertion for it "+
					"(redirectUrl=%q data=%q) -- the signed identity assertion for user %q would be delivered to an "+
					"attacker-chosen, unregistered URL", redirectUrl, data, user.Name)
			}
			if !strings.Contains(err.Error(), "AssertionConsumerServiceURL") {
				t.Fatalf("request was rejected, but not because of the untrusted AssertionConsumerServiceURL: %v", err)
			}
		})
	}
}
