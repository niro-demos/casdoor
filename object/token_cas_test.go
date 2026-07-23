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

// TestCheckCasTicketScope pins the CAS ticket-validation invariant: a service
// ticket may be redeemed ONLY when the caller's requested service URL exactly
// matches the URL the ticket was issued for, AND only at the
// organization/application path the ticket was actually issued under.
//
// Regression coverage for TC-EF09A131 (prefix-match bypass + org/app path
// ignored). Before the fix, validation used strings.HasPrefix(service,
// issuedService) and never read the :organization/:application route params, so
// the "prefix lookalike" and "cross org/app" cases below were accepted.
func TestCheckCasTicketScope(t *testing.T) {
	const (
		issuedService = "https://real-app-legit.example.com"
		org           = "org-alpha"
		app           = "app-alpha"
	)

	newWrapper := func() *CasAuthenticationSuccessWrapper {
		return &CasAuthenticationSuccessWrapper{
			AuthenticationSuccess: &CasAuthenticationSuccess{User: "alpha-admin"},
			Service:               issuedService,
			UserId:                "org-alpha/alpha-admin",
			Organization:          org,
			Application:           app,
		}
	}

	tests := []struct {
		name              string
		requestedService  string
		organization      string
		application       string
		wantCode          string // "" means validation must succeed
	}{
		// --- Legitimate control: exact service at the issuing path succeeds. ---
		{"exact service, correct org/app", issuedService, org, app, ""},

		// --- Bug 1: prefix-matched lookalike domain must be rejected. ---
		{
			"lookalike prefix domain rejected",
			issuedService + ".attacker.com/phish",
			org, app, "INVALID_SERVICE",
		},
		{
			"prefixed path on same host rejected",
			issuedService + "/../evil",
			org, app, "INVALID_SERVICE",
		},
		{
			"genuinely different service rejected",
			"https://totally-different.example.org",
			org, app, "INVALID_SERVICE",
		},

		// --- Bug 2: correct service but wrong org/app path must be rejected. ---
		{"exact service, wrong org", issuedService, "org-beta", app, "INVALID_SERVICE"},
		{"exact service, wrong app", issuedService, org, "app-beta", "INVALID_SERVICE"},
		{"exact service, wrong org and app", issuedService, "org-beta", "app-beta", "INVALID_SERVICE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckCasTicketScope(newWrapper(), tt.requestedService, queryUnescapeForTest(tt.requestedService), tt.organization, tt.application)
			if got != tt.wantCode {
				t.Errorf("CheckCasTicketScope(service=%q, org=%q, app=%q) = %q, want %q",
					tt.requestedService, tt.organization, tt.application, got, tt.wantCode)
			}
		})
	}
}

// TestCheckCasTicketScopeUnescapedServiceMatch documents that a
// percent-encoded requested service still validates when its unescaped form
// exactly matches the issued service (the legitimate encoding case), while a
// merely-prefixed one does not.
func TestCheckCasTicketScopeUnescapedServiceMatch(t *testing.T) {
	const issued = "https://real-app-legit.example.com/callback"
	w := &CasAuthenticationSuccessWrapper{Service: issued, Organization: "org-alpha", Application: "app-alpha"}

	// Legitimate: unescaped form matches exactly.
	if got := CheckCasTicketScope(w, "https%3A%2F%2Freal-app-legit.example.com%2Fcallback", issued, "org-alpha", "app-alpha"); got != "" {
		t.Errorf("exact unescaped service should validate, got %q", got)
	}
	// Attack: unescaped form only shares a prefix.
	evil := issued + ".attacker.com"
	if got := CheckCasTicketScope(w, evil, evil, "org-alpha", "app-alpha"); got != "INVALID_SERVICE" {
		t.Errorf("prefix lookalike must be rejected, got %q", got)
	}
}

// queryUnescapeForTest mirrors the raw+unescaped comparison the controller
// performs; for un-encoded inputs it is a no-op.
func queryUnescapeForTest(s string) string { return s }

// TestCheckCasLoginRejectsUnregisteredService pins the issuance-time invariant
// that the CAS ticket-issuing path now enforces (TC-2A5D7FF0): the SSO server
// must not hand out a signed CAS ticket for a destination URL that the target
// application has not registered as an allowed redirect URI.
//
// HandleLoggedIn's CAS branch now calls object.CheckCasLogin before
// GenerateCasToken (previously it minted a ticket for any attacker-supplied
// service). This test locks in CheckCasLogin's allowlist semantics so a
// regression that re-loosens issuance is caught.
func TestCheckCasLoginRejectsUnregisteredService(t *testing.T) {
	app := &Application{
		Owner:        "admin",
		Name:         "app-alpha",
		Organization: "org-alpha",
		RedirectUris: []string{"https://registered-good.example.com/callback"},
	}

	// Registered destination is accepted — the legitimate CAS login still works.
	if err := CheckCasLogin(app, "en", "https://registered-good.example.com/callback"); err != nil {
		t.Fatalf("registered service must be accepted, got error: %v", err)
	}

	// Unregistered, attacker-chosen destinations must be rejected at issuance.
	for _, evil := range []string{
		"https://evil.example.com/callback",
		"https://registered-good.example.com.attacker.com/phish",
		"https://attacker-controlled-2.example.net/steal",
	} {
		if err := CheckCasLogin(app, "en", evil); err == nil {
			t.Errorf("unregistered service %q must be rejected at CAS ticket issuance, but it was allowed", evil)
		}
	}
}
