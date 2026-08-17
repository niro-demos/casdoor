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
	"fmt"
	"testing"
	"time"
)

// TestCertsScopeGloballyOwnedCertsToGlobalAdminOnly is the regression test
// for TC-801D5964: GetCerts / GetCertCount / GetPaginationCerts
// unconditionally OR-merged every globally-owned cert (owner == "admin",
// which includes the platform's JWT-signing cert-built-in) into any org's
// cert listing, regardless of caller privilege. A tenant-scoped
// organization admin must not receive the platform's globally-owned certs
// (including their private keys) through its own org's cert listing; only
// the platform's global administrator may.
func TestCertsScopeGloballyOwnedCertsToGlobalAdminOnly(t *testing.T) {
	InitConfig()

	suffix := time.Now().UnixNano()
	orgOwner := fmt.Sprintf("niro-fix-cert-org-%d", suffix)
	globalCertName := fmt.Sprintf("niro-fix-global-cert-%d", suffix)

	globalCert := &Cert{Owner: "admin", Name: globalCertName, Scope: "JWT", Certificate: "dummy-cert", PrivateKey: "GLOBAL-PRIVATE-KEY"}
	orgCert := &Cert{Owner: orgOwner, Name: "org-cert", Scope: "JWT", Certificate: "dummy-cert", PrivateKey: "ORG-PRIVATE-KEY"}

	for _, c := range []*Cert{globalCert, orgCert} {
		if _, err := AddCert(c); err != nil {
			t.Fatalf("failed to seed cert %s/%s: %v", c.Owner, c.Name, err)
		}
	}
	t.Cleanup(func() {
		for _, c := range []*Cert{globalCert, orgCert} {
			if _, err := DeleteCert(c); err != nil {
				t.Logf("failed to clean up cert %s/%s: %v", c.Owner, c.Name, err)
			}
		}
	})

	containsGlobalCert := func(certs []*Cert) bool {
		for _, c := range certs {
			if c.Owner == "admin" && c.Name == globalCertName {
				return true
			}
		}
		return false
	}

	t.Run("GetCerts", func(t *testing.T) {
		// A tenant-scoped (non-global-admin) caller listing its own org's
		// certs must not receive the platform's globally-owned cert.
		certs, err := GetCerts(orgOwner, false)
		if err != nil {
			t.Fatal(err)
		}
		if containsGlobalCert(certs) {
			t.Fatalf("org-scoped caller (isGlobalAdmin=false) received the platform's globally-owned cert via GetCerts(%q, false): %+v", orgOwner, certs)
		}

		// Control: the true global admin must retain access to the merged view.
		certs, err = GetCerts(orgOwner, true)
		if err != nil {
			t.Fatal(err)
		}
		if !containsGlobalCert(certs) {
			t.Fatalf("global admin (isGlobalAdmin=true) did not receive the platform's globally-owned cert via GetCerts(%q, true): %+v", orgOwner, certs)
		}
	})

	t.Run("GetCertCount", func(t *testing.T) {
		// The environment may already contain other globally-owned certs
		// (e.g. the platform's real cert-built-in), so establish a baseline
		// count of *all* admin-owned certs (via a query for an owner that
		// cannot match any real org) rather than assuming our fixture is
		// the only one.
		nonexistentOwner := fmt.Sprintf("niro-fix-nonexistent-owner-%d", suffix)
		adminCertTotal, err := GetCertCount(nonexistentOwner, true, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if adminCertTotal < 1 {
			t.Fatalf("expected at least the seeded global cert to be counted, got %d admin-owned certs", adminCertTotal)
		}

		count, err := GetCertCount(orgOwner, false, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("org-scoped caller: GetCertCount(%q, false, ...) = %d, want 1 (only the org's own cert)", orgOwner, count)
		}

		count, err = GetCertCount(orgOwner, true, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if count != 1+adminCertTotal {
			t.Fatalf("global admin: GetCertCount(%q, true, ...) = %d, want %d (org cert + every admin-owned cert)", orgOwner, count, 1+adminCertTotal)
		}
	})

	t.Run("GetPaginationCerts", func(t *testing.T) {
		certs, err := GetPaginationCerts(orgOwner, false, 0, 10, "", "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if containsGlobalCert(certs) {
			t.Fatalf("org-scoped caller received the platform's globally-owned cert via GetPaginationCerts(%q, false, ...): %+v", orgOwner, certs)
		}

		certs, err = GetPaginationCerts(orgOwner, true, 0, 10, "", "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if !containsGlobalCert(certs) {
			t.Fatalf("global admin did not receive the platform's globally-owned cert via GetPaginationCerts(%q, true, ...): %+v", orgOwner, certs)
		}
	})
}
