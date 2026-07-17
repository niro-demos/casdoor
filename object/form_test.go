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

import "testing"

// TestUpdateFormRejectsCrossOrgOwnerChange is the regression test for
// TC-185A1D3F: an org-scoped (non-global) admin must not be able to write a
// form record into a different organization's namespace by setting a
// mismatched `owner` field in the update-form request body, even though the
// `id` query parameter still names a form the caller legitimately manages.
func TestUpdateFormRejectsCrossOrgOwnerChange(t *testing.T) {
	InitConfig()

	sourceOwner := "niro-test-org-a"
	targetOwner := "niro-test-org-b"
	name := "niro-test-form-cross-org"
	id := sourceOwner + "/" + name

	seed := &Form{
		Owner:       sourceOwner,
		Name:        name,
		DisplayName: "niro test form",
	}

	// Clean up any leftovers from a previous failed run, then seed fresh.
	_, _ = DeleteForm(&Form{Owner: sourceOwner, Name: name})
	_, _ = DeleteForm(&Form{Owner: targetOwner, Name: name})

	ok, err := AddForm(seed)
	if err != nil || !ok {
		t.Fatalf("setup: AddForm failed: ok=%v err=%v", ok, err)
	}
	defer func() {
		_, _ = DeleteForm(&Form{Owner: sourceOwner, Name: name})
		_, _ = DeleteForm(&Form{Owner: targetOwner, Name: name})
	}()

	// Attack: caller is authorized for id=sourceOwner/name (an org-scoped,
	// non-global admin), but the request body's owner names a different org.
	malicious := &Form{
		Owner:       targetOwner,
		Name:        name,
		DisplayName: "moved-by-attacker",
	}

	_, err = UpdateForm(id, malicious, false, "en")
	if err == nil {
		t.Fatalf("invariant violated: UpdateForm allowed a non-global-admin to change owner from %q to %q without error", sourceOwner, targetOwner)
	}

	relocated, getErr := getForm(targetOwner, name)
	if getErr != nil {
		t.Fatalf("getForm(%s) failed: %v", targetOwner, getErr)
	}
	if relocated != nil {
		t.Fatalf("invariant violated: form record was relocated into %q", targetOwner)
	}

	original, getErr := getForm(sourceOwner, name)
	if getErr != nil {
		t.Fatalf("getForm(%s) failed: %v", sourceOwner, getErr)
	}
	if original == nil {
		t.Fatalf("invariant violated: form record disappeared from its own org %q", sourceOwner)
	}
	if original.DisplayName != seed.DisplayName {
		t.Fatalf("invariant violated: form record was mutated by the rejected cross-org update, DisplayName=%q", original.DisplayName)
	}

	// Control: a same-org update (legitimate) must still succeed, proving the
	// rejection above is about the owner mismatch, not a broken environment.
	legit := &Form{
		Owner:       sourceOwner,
		Name:        name,
		DisplayName: "legit-same-org-update",
	}
	ok, err = UpdateForm(id, legit, false, "en")
	if err != nil || !ok {
		t.Fatalf("control failed: same-org update should succeed, ok=%v err=%v", ok, err)
	}
}
