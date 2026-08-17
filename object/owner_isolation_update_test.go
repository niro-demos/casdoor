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
	"testing"

	"github.com/xorm-io/core"
)

// These tests cover TC-0799CD4C: a caller who is only authorized on ownerA
// (the owner derived from the `id` query param, which is what the router's
// authz check validates) must not be able to move/plant a permission,
// adapter, or invitation into ownerB's namespace by setting the request
// body's "owner" field to ownerB, while `id` still points at an object the
// caller legitimately owns under ownerA.
//
// Each test asserts the invariant with a paired legitimate control: a
// same-owner update must keep succeeding (so the fix only closes the
// cross-owner path, it doesn't break normal updates), and the cross-owner
// update must be rejected, with the row remaining owned by ownerA and never
// appearing under ownerB.

func TestUpdatePermissionRejectsOwnerMismatch(t *testing.T) {
	InitConfig()

	const ownerA = "test-owner-a-perm"
	const ownerB = "test-owner-b-perm"
	const name = "test-perm-owner-check"

	cleanup := func() {
		_, _ = ormer.Engine.ID(core.PK{ownerA, name}).Delete(&Permission{})
		_, _ = ormer.Engine.ID(core.PK{ownerB, name}).Delete(&Permission{})
	}
	cleanup()
	defer cleanup()

	original := &Permission{
		Owner: ownerA, Name: name, DisplayName: "orig",
		ResourceType: "Application", Resources: []string{"res"},
		Actions: []string{"Read"}, Effect: "Allow", IsEnabled: true,
	}
	ok, err := AddPermission(original)
	if err != nil || !ok {
		t.Fatalf("setup: AddPermission failed: ok=%v err=%v", ok, err)
	}

	// Control: a legitimate same-owner update via the same id must keep working.
	legit := &Permission{
		Owner: ownerA, Name: name, DisplayName: "updated-legit",
		ResourceType: "Application", Resources: []string{"res"},
		Actions: []string{"Read"}, Effect: "Allow", IsEnabled: true,
	}
	affected, err := UpdatePermission(ownerA+"/"+name, legit, false, "en")
	if err != nil {
		t.Fatalf("legitimate same-owner update-permission should succeed, got error: %v", err)
	}
	if !affected {
		t.Fatalf("legitimate same-owner update-permission should report affected=true")
	}

	// Attack: id still points at ownerA's object, but the body's Owner is ownerB.
	malicious := &Permission{
		Owner: ownerB, Name: name, DisplayName: "planted",
		ResourceType: "Application", Resources: []string{"res"},
		Actions: []string{"Read"}, Effect: "Allow", IsEnabled: true,
	}
	affected, err = UpdatePermission(ownerA+"/"+name, malicious, false, "en")
	if err == nil {
		t.Fatalf("expected update-permission to reject owner mismatch (id owner %q vs body owner %q), got no error, affected=%v", ownerA, ownerB, affected)
	}

	planted, gErr := getPermission(ownerB, name)
	if gErr != nil {
		t.Fatalf("getPermission(ownerB) error: %v", gErr)
	}
	if planted != nil {
		t.Fatalf("cross-owner update-permission planted a record under %q: %+v", ownerB, planted)
	}

	stillA, gErr := getPermission(ownerA, name)
	if gErr != nil {
		t.Fatalf("getPermission(ownerA) error: %v", gErr)
	}
	if stillA == nil {
		t.Fatalf("permission disappeared from owner %q after rejected cross-owner update", ownerA)
	}
}

func TestUpdateAdapterRejectsOwnerMismatch(t *testing.T) {
	InitConfig()

	const ownerA = "test-owner-a-adapter"
	const ownerB = "test-owner-b-adapter"
	const name = "test-adapter-owner-check"

	cleanup := func() {
		_, _ = ormer.Engine.ID(core.PK{ownerA, name}).Delete(&Adapter{})
		_, _ = ormer.Engine.ID(core.PK{ownerB, name}).Delete(&Adapter{})
	}
	cleanup()
	defer cleanup()

	original := &Adapter{
		Owner: ownerA, Name: name, Type: "database", DatabaseType: "mysql",
		Host: "localhost", Port: 3306, User: "casdoor", Password: "casdoor",
		Database: "casdoor", Table: "adapter_owner_check",
	}
	ok, err := AddAdapter(original)
	if err != nil || !ok {
		t.Fatalf("setup: AddAdapter failed: ok=%v err=%v", ok, err)
	}

	// Control: a legitimate same-owner update via the same id must keep working.
	legit := &Adapter{
		Owner: ownerA, Name: name, Type: "database", DatabaseType: "mysql",
		Host: "localhost", Port: 3306, User: "casdoor", Password: "casdoor2",
		Database: "casdoor", Table: "adapter_owner_check",
	}
	affected, err := UpdateAdapter(ownerA+"/"+name, legit, false, "en")
	if err != nil {
		t.Fatalf("legitimate same-owner update-adapter should succeed, got error: %v", err)
	}
	if !affected {
		t.Fatalf("legitimate same-owner update-adapter should report affected=true")
	}

	// Attack: id still points at ownerA's object, but the body's Owner is ownerB,
	// with attacker-chosen host/credentials.
	malicious := &Adapter{
		Owner: ownerB, Name: name, Type: "database", DatabaseType: "mysql",
		Host: "evil.attacker.example", Port: 3306, User: "pwned_user", Password: "pwned_pw",
		Database: "casdoor", Table: "adapter_owner_check",
	}
	affected, err = UpdateAdapter(ownerA+"/"+name, malicious, false, "en")
	if err == nil {
		t.Fatalf("expected update-adapter to reject owner mismatch (id owner %q vs body owner %q), got no error, affected=%v", ownerA, ownerB, affected)
	}

	planted, gErr := getAdapter(ownerB, name)
	if gErr != nil {
		t.Fatalf("getAdapter(ownerB) error: %v", gErr)
	}
	if planted != nil {
		t.Fatalf("cross-owner update-adapter planted a record under %q: %+v", ownerB, planted)
	}

	stillA, gErr := getAdapter(ownerA, name)
	if gErr != nil {
		t.Fatalf("getAdapter(ownerA) error: %v", gErr)
	}
	if stillA == nil {
		t.Fatalf("adapter disappeared from owner %q after rejected cross-owner update", ownerA)
	}
}

func TestUpdateInvitationRejectsOwnerMismatch(t *testing.T) {
	InitConfig()

	const ownerA = "test-owner-a-invite"
	const ownerB = "test-owner-b-invite"
	const name = "test-invite-owner-check"

	cleanup := func() {
		_, _ = ormer.Engine.ID(core.PK{ownerA, name}).Delete(&Invitation{})
		_, _ = ormer.Engine.ID(core.PK{ownerB, name}).Delete(&Invitation{})
	}
	cleanup()
	defer cleanup()

	original := &Invitation{
		Owner: ownerA, Name: name, Code: "ORIGCODE1", DefaultCode: "ORIGCODE1",
		Quota: 5, UsedCount: 0, Application: "app-test",
	}
	ok, err := AddInvitation(original, "en")
	if err != nil || !ok {
		t.Fatalf("setup: AddInvitation failed: ok=%v err=%v", ok, err)
	}

	// Control: a legitimate same-owner update via the same id must keep working.
	legit := &Invitation{
		Owner: ownerA, Name: name, Code: "ORIGCODE2", DefaultCode: "ORIGCODE2",
		Quota: 5, UsedCount: 0, Application: "app-test",
	}
	affected, err := UpdateInvitation(ownerA+"/"+name, legit, false, "en")
	if err != nil {
		t.Fatalf("legitimate same-owner update-invitation should succeed, got error: %v", err)
	}
	if !affected {
		t.Fatalf("legitimate same-owner update-invitation should report affected=true")
	}

	// Attack: id still points at ownerA's object, but the body's Owner is ownerB,
	// with an attacker-chosen invitation code.
	malicious := &Invitation{
		Owner: ownerB, Name: name, Code: "EVILCODE", DefaultCode: "EVILCODE",
		Quota: 999, UsedCount: 0, Application: "app-test",
	}
	affected, err = UpdateInvitation(ownerA+"/"+name, malicious, false, "en")
	if err == nil {
		t.Fatalf("expected update-invitation to reject owner mismatch (id owner %q vs body owner %q), got no error, affected=%v", ownerA, ownerB, affected)
	}

	planted, gErr := getInvitation(ownerB, name)
	if gErr != nil {
		t.Fatalf("getInvitation(ownerB) error: %v", gErr)
	}
	if planted != nil {
		t.Fatalf("cross-owner update-invitation planted a record under %q: %+v", ownerB, planted)
	}

	stillA, gErr := getInvitation(ownerA, name)
	if gErr != nil {
		t.Fatalf("getInvitation(ownerA) error: %v", gErr)
	}
	if stillA == nil {
		t.Fatalf("invitation disappeared from owner %q after rejected cross-owner update", ownerA)
	}
}
