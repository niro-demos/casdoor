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

	"github.com/casdoor/casdoor/util"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
)

func containsCasbinRule(rules []*xormadapter.CasbinRule, v0, v1, v2 string) bool {
	for _, r := range rules {
		if r.V0 == v0 && r.V1 == v1 && r.V2 == v2 {
			return true
		}
	}
	return false
}

// TestEnforcerCrossOrgAdapterRejected is the regression test for TC-B4160A51:
// an organization-scoped admin must not be able to read or write another
// organization's policy rules -- including the global built-in
// organization's rules -- by registering an enforcer they own whose Adapter
// field points at the other organization's real adapter.
func TestEnforcerCrossOrgAdapterRejected(t *testing.T) {
	InitConfig()

	victimOwner := "niro-test-victim-org"
	attackerOwner := "niro-test-attacker-org"
	victimAdapterName := "niro-test-victim-adapter"
	victimEnforcerName := "niro-test-victim-enforcer"
	crossRefEnforcerName := "niro-test-cross-ref-enforcer"
	selfAdapterName := "niro-test-self-adapter"
	selfEnforcerName := "niro-test-self-enforcer"
	victimTable := "niro_test_victim_policy"
	selfTable := "niro_test_self_policy"

	victimAdapterId := util.GetId(victimOwner, victimAdapterName)
	victimEnforcerId := util.GetId(victimOwner, victimEnforcerName)
	crossRefEnforcerId := util.GetId(attackerOwner, crossRefEnforcerName)
	selfAdapterId := util.GetId(attackerOwner, selfAdapterName)
	selfEnforcerId := util.GetId(attackerOwner, selfEnforcerName)

	cleanup := func() {
		_, _ = DeleteEnforcer(&Enforcer{Owner: attackerOwner, Name: crossRefEnforcerName})
		_, _ = DeleteEnforcer(&Enforcer{Owner: attackerOwner, Name: selfEnforcerName})
		_, _ = DeleteAdapter(&Adapter{Owner: attackerOwner, Name: selfAdapterName})
		_, _ = DeleteEnforcer(&Enforcer{Owner: victimOwner, Name: victimEnforcerName})
		_, _ = DeleteAdapter(&Adapter{Owner: victimOwner, Name: victimAdapterName})
		_, _ = ormer.Engine.Exec("DROP TABLE IF EXISTS " + victimTable)
		_, _ = ormer.Engine.Exec("DROP TABLE IF EXISTS " + selfTable)
	}
	cleanup()
	defer cleanup()

	// --- Set up the victim's real adapter + enforcer, seeded with one
	// baseline "secret" policy row -- this is the other organization's real,
	// live data that must stay isolated. ---
	if _, err := AddAdapter(&Adapter{Owner: victimOwner, Name: victimAdapterName, Table: victimTable, UseSameDb: true}); err != nil {
		t.Fatalf("setup: failed to create victim adapter: %v", err)
	}
	if _, err := AddEnforcer(&Enforcer{Owner: victimOwner, Name: victimEnforcerName, DisplayName: "Victim Enforcer", Model: "built-in/user-model-built-in", Adapter: victimAdapterId}); err != nil {
		t.Fatalf("setup: failed to create victim enforcer: %v", err)
	}
	if _, err := AddPolicy(victimEnforcerId, "p", []string{victimOwner + "/admin", "secret-object", "read"}); err != nil {
		t.Fatalf("setup: failed to seed baseline policy: %v", err)
	}

	baseline, err := GetPolicies(victimEnforcerId)
	if err != nil {
		t.Fatalf("setup: failed to read back baseline policy: %v", err)
	}
	if !containsCasbinRule(baseline, victimOwner+"/admin", "secret-object", "read") {
		t.Fatalf("setup: baseline policy row not found after seeding: %+v", baseline)
	}

	// --- Invariant 1: creating a self-owned enforcer whose Adapter points at
	// another organization's real adapter must be rejected outright. ---
	_, err = AddEnforcer(&Enforcer{Owner: attackerOwner, Name: crossRefEnforcerName, DisplayName: "Cross Ref", Model: "built-in/user-model-built-in", Adapter: victimAdapterId})
	if err == nil {
		t.Fatalf("AddEnforcer should have rejected an enforcer (owner=%s) whose Adapter (%s) belongs to a different organization, but it succeeded", attackerOwner, victimAdapterId)
	}
	if e, _ := GetEnforcer(crossRefEnforcerId); e != nil {
		t.Fatalf("cross-org enforcer %s was persisted despite AddEnforcer returning an error", crossRefEnforcerId)
	}

	// --- Invariant 2 (defense in depth): even if such a row already exists
	// in the database -- legacy data, or any future path that bypasses
	// AddEnforcer's own guard -- the policy read/write handlers must not
	// follow its Adapter across the tenant boundary. Insert the row directly
	// (bypassing AddEnforcer) to simulate that pre-existing state. ---
	if _, err := ormer.Engine.Insert(&Enforcer{Owner: attackerOwner, Name: crossRefEnforcerName, DisplayName: "Cross Ref (raw)", Model: "built-in/user-model-built-in", Adapter: victimAdapterId}); err != nil {
		t.Fatalf("setup: failed to insert raw cross-org enforcer row: %v", err)
	}

	if _, err := GetPolicies(crossRefEnforcerId); err == nil {
		t.Fatalf("GetPolicies(%s) should have been rejected for a cross-org adapter reference, but it succeeded", crossRefEnforcerId)
	}
	if _, err := AddPolicy(crossRefEnforcerId, "p", []string{attackerOwner + "/admin", "injected-object", "write"}); err == nil {
		t.Fatalf("AddPolicy(%s) should have been rejected for a cross-org adapter reference, but it succeeded", crossRefEnforcerId)
	}

	after, err := GetPolicies(victimEnforcerId)
	if err != nil {
		t.Fatalf("failed to re-read victim policy after attempted cross-org write: %v", err)
	}
	if containsCasbinRule(after, attackerOwner+"/admin", "injected-object", "write") {
		t.Fatalf("cross-org write leaked into the victim's real policy store: %+v", after)
	}

	// --- Positive control: a fully self-owned enforcer (adapter also owned
	// by attackerOwner) must keep working normally -- proves the fix is
	// targeted at the cross-org reference, not enforcer CRUD in general. ---
	if _, err := AddAdapter(&Adapter{Owner: attackerOwner, Name: selfAdapterName, Table: selfTable, UseSameDb: true}); err != nil {
		t.Fatalf("setup: failed to create self adapter: %v", err)
	}
	if _, err := AddEnforcer(&Enforcer{Owner: attackerOwner, Name: selfEnforcerName, DisplayName: "Self Enforcer", Model: "built-in/user-model-built-in", Adapter: selfAdapterId}); err != nil {
		t.Fatalf("self-owned enforcer creation should succeed, got error: %v", err)
	}
	if _, err := AddPolicy(selfEnforcerId, "p", []string{attackerOwner + "/admin", "own-object", "read"}); err != nil {
		t.Fatalf("self-owned policy write should succeed, got error: %v", err)
	}
	selfPolicies, err := GetPolicies(selfEnforcerId)
	if err != nil {
		t.Fatalf("self-owned policy read should succeed, got error: %v", err)
	}
	if !containsCasbinRule(selfPolicies, attackerOwner+"/admin", "own-object", "read") {
		t.Fatalf("self-owned policy write did not read back: %+v", selfPolicies)
	}
}
