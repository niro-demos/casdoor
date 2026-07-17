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

// TestUpdatePermissionRejectsCrossOrgOwnerChange is the regression test for
// TC-C9DDFFFA: an org-scoped (non-global) admin must not be able to relocate
// a permission record into a different organization by setting a mismatched
// `owner` field in the update-permission request body, even though the `id`
// query parameter still names a permission the caller legitimately manages.
func TestUpdatePermissionRejectsCrossOrgOwnerChange(t *testing.T) {
	InitConfig()

	sourceOwner := "niro-test-org-a"
	targetOwner := "niro-test-org-b"
	name := "niro-test-perm-cross-org"
	id := sourceOwner + "/" + name

	seed := &Permission{
		Owner:       sourceOwner,
		Name:        name,
		DisplayName: "niro test permission",
		Users:       []string{sourceOwner + "/alice"},
		Resources:   []string{"niro-resource"},
		Actions:     []string{"Read"},
		Effect:      "Allow",
		IsEnabled:   true,
		Model:       "built-in/user-model-built-in",
	}

	// Clean up any leftovers from a previous failed run, then seed fresh.
	_, _ = DeletePermission(&Permission{Owner: sourceOwner, Name: name})
	_, _ = DeletePermission(&Permission{Owner: targetOwner, Name: name})

	ok, err := AddPermission(seed)
	if err != nil || !ok {
		t.Fatalf("setup: AddPermission failed: ok=%v err=%v", ok, err)
	}
	defer func() {
		_, _ = DeletePermission(&Permission{Owner: sourceOwner, Name: name})
		_, _ = DeletePermission(&Permission{Owner: targetOwner, Name: name})
	}()

	// Attack: caller is authorized for id=sourceOwner/name (an org-scoped,
	// non-global admin), but the request body's owner names a different org.
	malicious := &Permission{
		Owner:       targetOwner,
		Name:        name,
		DisplayName: "moved-by-attacker",
		Users:       []string{targetOwner + "/mallory"},
		Resources:   []string{"moved-resource"},
		Actions:     []string{"Read"},
		Effect:      "Allow",
		IsEnabled:   true,
		Model:       "built-in/user-model-built-in",
	}

	_, err = UpdatePermission(id, malicious, false, "en")
	if err == nil {
		t.Fatalf("invariant violated: UpdatePermission allowed a non-global-admin to change owner from %q to %q without error", sourceOwner, targetOwner)
	}

	relocated, getErr := getPermission(targetOwner, name)
	if getErr != nil {
		t.Fatalf("getPermission(%s) failed: %v", targetOwner, getErr)
	}
	if relocated != nil {
		t.Fatalf("invariant violated: permission record was relocated into %q", targetOwner)
	}

	original, getErr := getPermission(sourceOwner, name)
	if getErr != nil {
		t.Fatalf("getPermission(%s) failed: %v", sourceOwner, getErr)
	}
	if original == nil {
		t.Fatalf("invariant violated: permission record disappeared from its own org %q", sourceOwner)
	}
	if original.DisplayName != seed.DisplayName {
		t.Fatalf("invariant violated: permission record was mutated by the rejected cross-org update, DisplayName=%q", original.DisplayName)
	}

	// Control: a same-org update (legitimate) must still succeed, proving the
	// rejection above is about the owner mismatch, not a broken environment.
	legit := &Permission{
		Owner:       sourceOwner,
		Name:        name,
		DisplayName: "legit-same-org-update",
		Users:       []string{sourceOwner + "/alice"},
		Resources:   []string{"niro-resource"},
		Actions:     []string{"Read"},
		Effect:      "Allow",
		IsEnabled:   true,
		Model:       "built-in/user-model-built-in",
	}
	ok, err = UpdatePermission(id, legit, false, "en")
	if err != nil || !ok {
		t.Fatalf("control failed: same-org update should succeed, ok=%v err=%v", ok, err)
	}
}
