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
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
)

// Invariant under test (TC-1F5276A2): when Casdoor acts as a SAML identity
// provider, it must only deliver a user's signed SAML assertion to an
// Assertion Consumer Service URL that is registered for the requesting
// application (via SamlReplyUrl or the application's RedirectUris), never to
// any URL the login request itself supplies.
const (
	samlAcsTestOwner       = "admin"
	samlAcsTestLegitURI    = "http://localhost:19001/callback"
	samlAcsTestAttackerACS = "https://evil.example.com/saml-acs"
)

// samlAcsTestResponse captures just the fields needed to assert the
// invariant from a decoded <samlp:Response>.
type samlAcsTestResponse struct {
	XMLName     xml.Name `xml:"Response"`
	Destination string   `xml:"Destination,attr"`
	Assertion   struct {
		Subject struct {
			SubjectConfirmation struct {
				SubjectConfirmationData struct {
					Recipient string `xml:"Recipient,attr"`
				} `xml:"SubjectConfirmationData"`
			} `xml:"SubjectConfirmation"`
		} `xml:"Subject"`
	} `xml:"Assertion"`
}

// buildSamlAcsTestAuthnRequest builds a raw (undeflated) <samlp:AuthnRequest>
// XML document, matching the format GetSamlResponse accepts when it contains
// "xmlns:" (see object/saml_idp.go GetSamlResponse).
func buildSamlAcsTestAuthnRequest(id, issuer, acsURL string) string {
	return fmt.Sprintf(
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="2026-08-17T00:00:00Z" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		id, acsURL, issuer,
	)
}

// setUpSamlAcsTestApplication creates a minimal, isolated SAML application
// (with its own real certificate) for the ACS-URL trust tests below.
// SamlReplyUrl is left empty (the default for every seeded application, and
// the condition under which the vulnerability was observed live) so the
// application's RedirectUris are the only registered ACS allow-list.
func setUpSamlAcsTestApplication(t *testing.T, name string) *Application {
	t.Helper()
	InitConfig()

	certName := name + "-cert"
	certPem, keyPem, err := generateRsaKeys(1024, 256, 1, "saml-acs-test", "casdoor")
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	cert := &Cert{
		Owner:       samlAcsTestOwner,
		Name:        certName,
		Certificate: certPem,
		PrivateKey:  keyPem,
	}
	ok, err := AddCert(cert)
	if err != nil || !ok {
		t.Fatalf("failed to add test cert: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = DeleteCert(cert)
	})

	application := &Application{
		Owner:                 samlAcsTestOwner,
		Name:                  name,
		Organization:          "saml-acs-test-org",
		Cert:                  certName,
		RedirectUris:          []string{samlAcsTestLegitURI},
		SamlReplyUrl:          "",
		DisableSamlAttributes: true,
	}
	ok, err = AddApplication(application)
	if err != nil || !ok {
		t.Fatalf("failed to add test application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = DeleteApplication(application)
	})

	return application
}

// TestGetSamlResponseRejectsUnregisteredAssertionConsumerServiceURL is the
// red case for TC-1F5276A2: a login request whose Issuer is legitimately
// registered but whose AssertionConsumerServiceURL is an attacker-controlled,
// unregistered URL must not receive a signed assertion addressed to that URL.
func TestGetSamlResponseRejectsUnregisteredAssertionConsumerServiceURL(t *testing.T) {
	application := setUpSamlAcsTestApplication(t, "test-saml-acs-attack-app")
	user := &User{Owner: samlAcsTestOwner, Name: "alice", Email: "alice@example.test", DisplayName: "Alice"}

	reqXML := buildSamlAcsTestAuthnRequest("_pocreq-attack", samlAcsTestLegitURI, samlAcsTestAttackerACS)
	samlRequest := base64.StdEncoding.EncodeToString([]byte(reqXML))

	data, acsURL, _, err := GetSamlResponse(application, user, samlRequest, "127.0.0.1:18000")

	if err == nil {
		destination, recipient := "<undecodable>", "<undecodable>"
		if rawXML, decodeErr := base64.StdEncoding.DecodeString(data); decodeErr == nil {
			var sr samlAcsTestResponse
			if xml.Unmarshal(rawXML, &sr) == nil {
				destination = sr.Destination
				recipient = sr.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient
			}
		}
		t.Fatalf("expected GetSamlResponse to reject an unregistered AssertionConsumerServiceURL, but it returned a signed assertion: acsURL=%q, response Destination=%q, Recipient=%q",
			acsURL, destination, recipient)
	}

	if !strings.Contains(err.Error(), samlAcsTestAttackerACS) {
		t.Fatalf("GetSamlResponse rejected the request, but the error doesn't reference the invalid ACS URL (want it to name %q): %v", samlAcsTestAttackerACS, err)
	}
}

// TestGetSamlResponseAllowsRegisteredAssertionConsumerServiceURL is the
// positive control: a login request whose AssertionConsumerServiceURL
// matches the application's registered RedirectUris must keep working,
// proving the fix narrows only the unregistered-URL case.
func TestGetSamlResponseAllowsRegisteredAssertionConsumerServiceURL(t *testing.T) {
	application := setUpSamlAcsTestApplication(t, "test-saml-acs-legit-app")
	user := &User{Owner: samlAcsTestOwner, Name: "alice", Email: "alice@example.test", DisplayName: "Alice"}

	reqXML := buildSamlAcsTestAuthnRequest("_pocreq-legit", samlAcsTestLegitURI, samlAcsTestLegitURI)
	samlRequest := base64.StdEncoding.EncodeToString([]byte(reqXML))

	data, acsURL, _, err := GetSamlResponse(application, user, samlRequest, "127.0.0.1:18000")
	if err != nil {
		t.Fatalf("expected a SAML login whose ACS URL matches a registered RedirectUri to succeed, got error: %v", err)
	}
	if acsURL != samlAcsTestLegitURI {
		t.Fatalf("acsURL = %q, want %q", acsURL, samlAcsTestLegitURI)
	}

	rawXML, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatalf("failed to decode SAML response: %v", err)
	}
	var sr samlAcsTestResponse
	if err := xml.Unmarshal(rawXML, &sr); err != nil {
		t.Fatalf("failed to unmarshal SAML response: %v", err)
	}
	if sr.Destination != samlAcsTestLegitURI {
		t.Fatalf("Response Destination = %q, want %q", sr.Destination, samlAcsTestLegitURI)
	}
	if sr.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != samlAcsTestLegitURI {
		t.Fatalf("SubjectConfirmationData Recipient = %q, want %q", sr.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient, samlAcsTestLegitURI)
	}
}
