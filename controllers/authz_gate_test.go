// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

// Actor shapes reused by the regression tests below. They mirror the three
// actors the black-box PoCs exercised against the live app:
//   - nonAdmin      : a plain tenant user (no admin, not global)   -> masked / denied
//   - orgScopedAdmin: an org admin (IsAdmin, Owner is a tenant org) -> masked / denied
//   - globalAdmin   : a true site admin (Owner == "built-in")       -> unmasked / allowed
//
// The security-relevant case is orgScopedAdmin: the pre-fix code gated on
// c.IsAdmin(), which is true for this actor, so it wrongly cleared the gate. The
// invariant is that platform-owned secret exposure and platform-global
// operations key off IsGlobalAdmin() (Owner == "built-in"), so this actor is
// treated exactly like a non-admin. IsGlobalAdmin() is the same predicate the
// fixed handlers (GetCerts masking, RefreshEngines gate) rely on via
// c.IsGlobalAdmin().
var (
	nonAdmin       = &object.User{Owner: "org-alpha", Name: "alpha-user", IsAdmin: false}
	orgScopedAdmin = &object.User{Owner: "org-alpha", Name: "alpha-admin", IsAdmin: true}
	globalAdmin    = &object.User{Owner: "built-in", Name: "admin", IsAdmin: true}
)

// platformSigningCert models the shared, platform-owned ("admin"-owned) JWT
// signing certificate that object.GetCerts returns to every org (its query is
// `owner = 'admin' OR owner = <caller-org>`). Its private key is the material
// the leak exposes.
func platformSigningCert() *object.Cert {
	return &object.Cert{
		Owner:      "admin",
		Name:       "cert-built-in",
		Scope:      "JWT",
		PrivateKey: "-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJB...redacted...\n-----END RSA PRIVATE KEY-----",
	}
}

// TC-57258EC2: an org-scoped admin must NOT receive the platform-owned signing
// cert's plaintext private key from the cert-list handlers; only a global admin
// may. Exercises maskCertsForViewer — the exact choke point GetCerts (both the
// paginated and non-paginated branches) now uses — with the IsGlobalAdmin()
// verdict for each actor, and asserts the masking invariant. The org-scoped
// admin case is the one that leaked before the fix.
func TestMaskCertsForViewer_OrgAdminNeverSeesPlatformPrivateKey(t *testing.T) {
	cases := []struct {
		name         string
		viewer       *object.User
		wantUnmasked bool // true => plaintext private key visible (global admin only)
	}{
		{"non-admin tenant user", nonAdmin, false},
		{"org-scoped admin (owner != built-in)", orgScopedAdmin, false},
		{"global admin (owner == built-in)", globalAdmin, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The handlers call maskCertsForViewer(certs, c.IsGlobalAdmin());
			// user.IsGlobalAdmin() is exactly what c.IsGlobalAdmin() resolves to
			// for a signed-in user, so drive the choke point the same way.
			certs, err := maskCertsForViewer([]*object.Cert{platformSigningCert()}, tc.viewer.IsGlobalAdmin())
			if err != nil {
				t.Fatalf("maskCertsForViewer returned error: %v", err)
			}
			if len(certs) != 1 {
				t.Fatalf("expected 1 cert, got %d", len(certs))
			}
			got := certs[0]

			leakedPlaintext := got.Owner == "admin" &&
				got.PrivateKey != "" && got.PrivateKey != "***"

			if tc.wantUnmasked {
				if !leakedPlaintext {
					t.Fatalf("global admin should see the plaintext private key, but it was masked: %q", got.PrivateKey)
				}
			} else {
				// The invariant: a non-global-admin viewer must NEVER receive the
				// platform-owned cert's plaintext private key.
				if leakedPlaintext {
					t.Fatalf("INVARIANT VIOLATED: viewer %s/%s (IsAdmin=%v, IsGlobalAdmin=%v) received the "+
						"platform-owned signing cert's PLAINTEXT private key (len=%d). "+
						"Non-global admins must only ever see it masked as \"***\".",
						tc.viewer.Owner, tc.viewer.Name, tc.viewer.IsAdmin, tc.viewer.IsGlobalAdmin(),
						len(got.PrivateKey))
				}
				if got.PrivateKey != "***" {
					t.Fatalf("expected masked private key \"***\" for %s, got %q", tc.name, got.PrivateKey)
				}
			}
		})
	}
}

// TC-1F312E1B: an org-scoped admin must NOT be able to trigger the server-wide
// CLI-engine refresh; only a global admin may. RefreshEngines gates on
// !c.IsGlobalAdmin(); c.IsGlobalAdmin() resolves to user.IsGlobalAdmin() for a
// signed-in caller, so this asserts that predicate — the fix's gate — allows
// only the global admin and rejects the org-scoped admin exactly like a plain
// non-admin.
func TestRefreshEnginesGate_OnlyGlobalAdmin(t *testing.T) {
	cases := []struct {
		name  string
		user  *object.User
		allow bool
	}{
		{"non-admin tenant user", nonAdmin, false},
		{"org-scoped admin (owner != built-in)", orgScopedAdmin, false},
		{"global admin (owner == built-in)", globalAdmin, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The handler's authorization gate is: allowed == c.IsGlobalAdmin().
			got := tc.user.IsGlobalAdmin()
			if got != tc.allow {
				t.Fatalf("INVARIANT VIOLATED: RefreshEngines gate for %s/%s (IsAdmin=%v) = %v, want %v. "+
					"Only a true global admin (Owner==\"built-in\") may trigger the platform-wide CLI-engine refresh; "+
					"an org-scoped admin must be rejected like a plain non-admin.",
					tc.user.Owner, tc.user.Name, tc.user.IsAdmin, got, tc.allow)
			}
		})
	}
}
