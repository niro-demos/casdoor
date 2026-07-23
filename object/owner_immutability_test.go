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

// These are the regression tests for the site/rule owner-repointing hijack:
// UpdateSite / UpdateSiteNoRefresh / UpdateRule persist every column from the
// request body via AllCols().Update(struct), so a body carrying
// `"owner":"<foreign-org>"` would repoint the record's primary key into another
// tenant. The fix has each Update function call the record's bindKeyFromId(id)
// to bind the persisted Owner/Name to the id-derived key before the write. These
// tests exercise that exact binding method — the fix's own code path — without
// needing a live database.

// TestUpdateSiteBindsOwnerNameToId is the regression test for the site vector.
//
// Invariant: an org admin who owns a site must not be able to move it into
// another organization's tenant by putting a foreign `owner` in the update body.
func TestUpdateSiteBindsOwnerNameToId(t *testing.T) {
	const id = "org-alpha/alpha-site2-TS" // authorized via the caller's own org

	// Attacker-controlled body: owner repointed to org-beta, plus a hijacked
	// name and payload domain — exactly the malicious update-site request.
	site := &Site{
		Owner:       "org-beta",
		Name:        "HIJACKED",
		DisplayName: "HIJACKED",
		Domain:      "hijacked2.example.com",
	}

	// This is the guard UpdateSite / UpdateSiteNoRefresh apply before
	// AllCols().Update(site).
	site.bindKeyFromId(id)

	if site.Owner != "org-alpha" {
		t.Fatalf("owner hijack: persisted owner = %q, want %q "+
			"(body owner must not repoint the record across tenants)",
			site.Owner, "org-alpha")
	}
	if site.Name != "alpha-site2-TS" {
		t.Fatalf("name hijack: persisted name = %q, want %q",
			site.Name, "alpha-site2-TS")
	}
}

// TestUpdateRuleBindsOwnerNameToId is the regression test for the rule vector.
//
// Invariant: an org admin who owns an access rule must not be able to move it
// into another organization's tenant via a foreign `owner` in the update body.
func TestUpdateRuleBindsOwnerNameToId(t *testing.T) {
	const id = "org-alpha/alpha-rule-TS"

	rule := &Rule{
		Owner:  "org-beta",
		Name:   "HIJACKED",
		Type:   "Rule",
		Action: "Deny",
		Reason: "HIJACKED",
	}

	// This is the guard UpdateRule applies before AllCols().Update(rule).
	rule.bindKeyFromId(id)

	if rule.Owner != "org-alpha" {
		t.Fatalf("owner hijack: persisted owner = %q, want %q",
			rule.Owner, "org-alpha")
	}
	if rule.Name != "alpha-rule-TS" {
		t.Fatalf("name hijack: persisted name = %q, want %q",
			rule.Name, "alpha-rule-TS")
	}
}

// TestUpdateLegitimateSameTenantOwnerUnchanged is the positive control: a
// legitimate same-tenant update (body owner already matches the id's owner)
// must be unaffected by the guard, proving the fix blocks only the cross-tenant
// repoint, not normal edits.
func TestUpdateLegitimateSameTenantOwnerUnchanged(t *testing.T) {
	const id = "org-alpha/alpha-site2-TS"

	site := &Site{
		Owner:       "org-alpha",
		Name:        "alpha-site2-TS",
		DisplayName: "Alpha Site 2 (legit edit)",
		Domain:      "alpha2-legit.example.com",
	}

	site.bindKeyFromId(id)

	if site.Owner != "org-alpha" || site.Name != "alpha-site2-TS" {
		t.Fatalf("legitimate update altered key: got (%q, %q), want (%q, %q)",
			site.Owner, site.Name, "org-alpha", "alpha-site2-TS")
	}
	// The editable fields the caller legitimately changed remain intact.
	if site.DisplayName != "Alpha Site 2 (legit edit)" || site.Domain != "alpha2-legit.example.com" {
		t.Fatalf("legitimate update lost editable fields: %+v", site)
	}
}
