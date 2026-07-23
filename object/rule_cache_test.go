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
	"strings"
	"testing"

	"github.com/casdoor/casdoor/util"
)

// TestGetRulesByRuleIdsWithOwner_CrossOrgIsolation asserts the security
// invariant behind TC-7F3BAA2C:
//
//	An org admin resolving referenced access-rule IDs (e.g. while creating or
//	evaluating a Compound rule owned by their org) must NOT be able to resolve
//	a rule owned by a DIFFERENT organization, and must NOT be able to tell —
//	from the error — whether that other org's rule name exists (no enumeration
//	oracle). Same-org rules and globally-shared "admin"-owned rules resolve
//	normally.
//
// This runs against the in-memory ruleMap directly, so it needs no database.
func TestGetRulesByRuleIdsWithOwner_CrossOrgIsolation(t *testing.T) {
	// Snapshot and restore the package-level ruleMap so we don't disturb
	// other tests in the suite.
	saved := ruleMap
	defer func() { ruleMap = saved }()

	betaRuleId := util.GetId("org-beta", "beta-secret-rule")   // private to org-beta
	alphaRuleId := util.GetId("org-alpha", "alpha-own-rule")   // owned by org-alpha
	globalRuleId := util.GetId("admin", "global-shared-rule")  // globally shared
	missingRuleId := util.GetId("org-beta", "does-not-exist")  // never seeded

	ruleMap = map[string]*Rule{
		betaRuleId:   {Owner: "org-beta", Name: "beta-secret-rule", Type: "IP"},
		alphaRuleId:  {Owner: "org-alpha", Name: "alpha-own-rule", Type: "IP"},
		globalRuleId: {Owner: "admin", Name: "global-shared-rule", Type: "IP"},
	}

	// Control 1 (green): an org-alpha rule may reference its own org's rule.
	if _, err := GetRulesByRuleIdsWithOwner([]string{alphaRuleId}, "org-alpha"); err != nil {
		t.Fatalf("control failed: org-alpha should resolve its OWN rule, got error: %v", err)
	}

	// Control 2 (green): any org may reference a globally-shared "admin" rule.
	if _, err := GetRulesByRuleIdsWithOwner([]string{globalRuleId}, "org-alpha"); err != nil {
		t.Fatalf("control failed: org-alpha should resolve the global admin rule, got error: %v", err)
	}

	// Exploit A: org-alpha references a REAL org-beta private rule.
	// Invariant: this cross-org reference must be REJECTED.
	_, crossErr := GetRulesByRuleIdsWithOwner([]string{betaRuleId}, "org-alpha")
	if crossErr == nil {
		t.Fatalf("VULNERABLE: org-alpha resolved org-beta's private rule %q across the tenant boundary", betaRuleId)
	}

	// Exploit B: org-alpha references a name that does NOT exist in org-beta.
	_, missingErr := GetRulesByRuleIdsWithOwner([]string{missingRuleId}, "org-alpha")
	if missingErr == nil {
		t.Fatalf("expected an error for a nonexistent rule %q", missingRuleId)
	}

	// Oracle invariant: the error for a REAL cross-org rule must be
	// indistinguishable from the error for a truly-missing one, once the
	// caller-supplied ID (which the attacker already knows) is normalized out.
	// Otherwise the accept-vs-"not found" divergence lets org-alpha enumerate
	// org-beta's private rule namespace. Here we compare the error *shape*: both
	// must be the same generic "rule: <id> not found" form, differing only in
	// the ID the caller itself provided.
	crossShape := strings.Replace(crossErr.Error(), betaRuleId, "<id>", 1)
	missingShape := strings.Replace(missingErr.Error(), missingRuleId, "<id>", 1)
	if crossShape != missingShape {
		t.Fatalf("ENUMERATION ORACLE: cross-org error shape %q differs from missing-rule error shape %q; "+
			"an org admin can distinguish 'exists in another org' from 'does not exist'",
			crossShape, missingShape)
	}
	if !strings.Contains(strings.ToLower(crossShape), "not found") {
		t.Fatalf("expected a generic 'not found' error, got: %q", crossErr.Error())
	}
}
