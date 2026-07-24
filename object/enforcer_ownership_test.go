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
	"testing"

	xormadapter "github.com/casdoor/xorm-adapter/v3"
	"github.com/xorm-io/xorm"
	_ "modernc.org/sqlite"
)

// setupOwnershipTestOrmer stands up a fully isolated, in-memory sqlite ormer so
// this security regression test never touches the real (MySQL) database or the
// running pentest target. Only the tables needed by the enforcer ownership check
// are synced.
func setupOwnershipTestOrmer(t *testing.T) func() {
	t.Helper()

	engine, err := xorm.NewEngine("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}

	if err = engine.Sync2(new(Model)); err != nil {
		t.Fatalf("sync Model: %v", err)
	}
	if err = engine.Sync2(new(Adapter)); err != nil {
		t.Fatalf("sync Adapter: %v", err)
	}
	if err = engine.Sync2(new(Enforcer)); err != nil {
		t.Fatalf("sync Enforcer: %v", err)
	}
	if err = engine.Sync2(new(xormadapter.CasbinRule)); err != nil {
		t.Fatalf("sync CasbinRule: %v", err)
	}

	prevOrmer := ormer
	ormer = &Ormer{Engine: engine}

	return func() {
		ormer = prevOrmer
		_ = engine.Close()
	}
}

// seedOwnershipFixtures recreates the actors/data the PoC exercised: a shared
// platform-owned ("built-in") model + adapter (the store only global admins
// should control), and a tenant ("acme") that owns its own model + adapter.
func seedOwnershipFixtures(t *testing.T) {
	t.Helper()

	builtInModel := &Model{Owner: "built-in", Name: "api-model-built-in", ModelText: "[request_definition]\nr = sub, obj, act"}
	builtInAdapter := &Adapter{Owner: "built-in", Name: "api-adapter-built-in", Table: "casbin_api_rule"}
	acmeModel := &Model{Owner: "acme", Name: "acme-model", ModelText: "[request_definition]\nr = sub, obj, act"}
	acmeAdapter := &Adapter{Owner: "acme", Name: "acme-adapter", Table: "acme_rule"}

	for _, row := range []interface{}{builtInModel, builtInAdapter, acmeModel, acmeAdapter} {
		if _, err := ormer.Engine.Insert(row); err != nil {
			t.Fatalf("seed fixture: %v", err)
		}
	}
}

// TestAddEnforcer_RejectsForeignModelAndAdapter asserts the security invariant:
// a tenant admin (enforcer.Owner="acme") must NOT be able to create an enforcer
// whose Model/Adapter reference a store owned by another org ("built-in"). This
// is the cross-tenant integrity boundary the PoC laundered a policy write
// through.
func TestAddEnforcer_RejectsForeignModelAndAdapter(t *testing.T) {
	cleanup := setupOwnershipTestOrmer(t)
	defer cleanup()
	seedOwnershipFixtures(t)

	// Attack: acme org-admin points its own enforcer at the built-in store.
	foreign := &Enforcer{
		Owner:   "acme",
		Name:    "acme-test-enforcer",
		Model:   "built-in/api-model-built-in",
		Adapter: "built-in/api-adapter-built-in",
	}

	affected, err := AddEnforcer(foreign)
	if err == nil {
		t.Fatalf("SECURITY: AddEnforcer accepted an enforcer owned by %q pointing at a store owned by built-in (affected=%v); it must be rejected", foreign.Owner, affected)
	}
	if affected {
		t.Fatalf("SECURITY: AddEnforcer reported the foreign-store enforcer as persisted despite the error")
	}

	// The row must not have reached storage.
	got, err := getEnforcer("acme", "acme-test-enforcer")
	if err != nil {
		t.Fatalf("getEnforcer: %v", err)
	}
	if got != nil {
		t.Fatalf("SECURITY: foreign-store enforcer was persisted despite rejection")
	}
}

// TestAddEnforcer_AllowsOwnModelAndAdapter is the paired legitimate control:
// an enforcer that references its OWN org's model/adapter must succeed, proving
// the rejection above is the ownership invariant and not a broken test setup.
func TestAddEnforcer_AllowsOwnModelAndAdapter(t *testing.T) {
	cleanup := setupOwnershipTestOrmer(t)
	defer cleanup()
	seedOwnershipFixtures(t)

	legit := &Enforcer{
		Owner:   "acme",
		Name:    "acme-own-enforcer",
		Model:   "acme/acme-model",
		Adapter: "acme/acme-adapter",
	}

	affected, err := AddEnforcer(legit)
	if err != nil {
		t.Fatalf("legitimate same-org enforcer was rejected: %v", err)
	}
	if !affected {
		t.Fatalf("legitimate same-org enforcer was not persisted")
	}
}

// TestAddEnforcer_AllowsGlobalAdminBuiltIn is the second legitimate control:
// a global admin operating in the built-in org (enforcer.Owner="built-in")
// referencing the built-in store must still work — the fix must not break the
// platform's own enforcer administration.
func TestAddEnforcer_AllowsGlobalAdminBuiltIn(t *testing.T) {
	cleanup := setupOwnershipTestOrmer(t)
	defer cleanup()
	seedOwnershipFixtures(t)

	builtIn := &Enforcer{
		Owner:   "built-in",
		Name:    "api-enforcer-built-in",
		Model:   "built-in/api-model-built-in",
		Adapter: "built-in/api-adapter-built-in",
	}

	affected, err := AddEnforcer(builtIn)
	if err != nil {
		t.Fatalf("global-admin built-in enforcer was rejected: %v", err)
	}
	if !affected {
		t.Fatalf("global-admin built-in enforcer was not persisted")
	}
}

// TestUpdateEnforcer_RejectsRepointToForeignStore asserts the same invariant on
// the update path: an org-admin who owns a legitimate enforcer must NOT be able
// to repoint it at a foreign (built-in) store after creation.
func TestUpdateEnforcer_RejectsRepointToForeignStore(t *testing.T) {
	cleanup := setupOwnershipTestOrmer(t)
	defer cleanup()
	seedOwnershipFixtures(t)

	// A legitimate, owned enforcer already exists.
	legit := &Enforcer{
		Owner:   "acme",
		Name:    "acme-own-enforcer",
		Model:   "acme/acme-model",
		Adapter: "acme/acme-adapter",
	}
	if _, err := AddEnforcer(legit); err != nil {
		t.Fatalf("setup: legitimate enforcer add failed: %v", err)
	}

	// Attack: repoint it at the built-in store.
	repointed := &Enforcer{
		Owner:   "acme",
		Name:    "acme-own-enforcer",
		Model:   "built-in/api-model-built-in",
		Adapter: "built-in/api-adapter-built-in",
	}

	affected, err := UpdateEnforcer("acme/acme-own-enforcer", repointed)
	if err == nil {
		t.Fatalf("SECURITY: UpdateEnforcer accepted repointing an acme enforcer at the built-in store (affected=%v); it must be rejected", affected)
	}

	// The persisted enforcer must still reference the acme adapter.
	got, err := getEnforcer("acme", "acme-own-enforcer")
	if err != nil {
		t.Fatalf("getEnforcer: %v", err)
	}
	if got == nil {
		t.Fatalf("enforcer disappeared")
	}
	if got.Adapter != "acme/acme-adapter" {
		t.Fatalf("SECURITY: enforcer was repointed to a foreign adapter: %q", got.Adapter)
	}
}
