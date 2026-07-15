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

// withRuleMap seeds the package-level rule cache for the duration of a test
// without touching the database, and restores the previous cache afterwards
// so this test cannot leak state into any other test that relies on ruleMap.
func withRuleMap(t *testing.T, rules map[string]*Rule) {
	t.Helper()
	original := ruleMap
	ruleMap = rules
	t.Cleanup(func() {
		ruleMap = original
	})
}

// TestCheckRulesOwnedByRejectsCrossOrgReference is the regression test for
// TC-F2A4568D: an organization admin must not be able to create a Compound
// rule that references or incorporates a rule owned by a different
// organization.
func TestCheckRulesOwnedByRejectsCrossOrgReference(t *testing.T) {
	withRuleMap(t, map[string]*Rule{
		"built-in/builtin-ip-rule": {Owner: "built-in", Name: "builtin-ip-rule", Type: "IP"},
		"acme/acme-ip-rule":        {Owner: "acme", Name: "acme-ip-rule", Type: "IP"},
	})

	// Positive control: acme referencing its own org's rule must be allowed.
	// If this fails, the test environment itself is broken and the negative
	// case below cannot be trusted.
	if err := CheckRulesOwnedBy("acme", []string{"acme/acme-ip-rule"}); err != nil {
		t.Fatalf("expected acme to reference its own rule without error, got: %v", err)
	}

	// The invariant: acme must not be able to reference built-in's rule.
	err := CheckRulesOwnedBy("acme", []string{"built-in/builtin-ip-rule"})
	if err == nil {
		t.Fatal("expected a cross-organization rule reference (acme -> built-in) to be rejected, got nil error")
	}
}

// TestCheckRulesOwnedByStillRejectsUnknownRule ensures the existence check
// that CheckRulesOwnedBy delegates to is preserved by the fix - it should
// still error when a referenced rule id does not exist anywhere, not just
// when it exists under a different owner.
func TestCheckRulesOwnedByStillRejectsUnknownRule(t *testing.T) {
	withRuleMap(t, map[string]*Rule{})

	err := CheckRulesOwnedBy("acme", []string{"built-in/does-not-exist"})
	if err == nil {
		t.Fatal("expected an error for a nonexistent referenced rule, got nil")
	}
}
