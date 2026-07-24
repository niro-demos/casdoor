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

	"github.com/casdoor/casdoor/log"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/names"
	_ "modernc.org/sqlite" // db = sqlite
)

// withHermeticOrmer installs a throwaway in-memory sqlite-backed ormer for the
// duration of a test and restores the previous one afterwards. It is fully
// isolated: it never reads conf/app.conf and never touches any external
// database, so it is safe to run in CI (and against any live target) without
// side effects.
func withHermeticOrmer(t *testing.T, beans ...interface{}) func() {
	t.Helper()

	engine, err := xorm.NewEngine("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite engine: %v", err)
	}
	// Match the snake_case table mapping the real adapter uses.
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))

	if err = engine.Sync2(beans...); err != nil {
		t.Fatalf("failed to sync schema: %v", err)
	}

	prev := ormer
	ormer = &Ormer{Engine: engine}

	return func() {
		ormer = prev
		_ = engine.Close()
	}
}

// TestOpenClawTelemetryAttributedToOwningOrg is the regression test for the
// tenant data-isolation invariant: telemetry ingested through an
// organization-owned OpenClaw agent provider must be attributed to that owning
// organization (Entry.Owner == provider.Owner), not force-written to the global
// "built-in" organization where every tenant's telemetry would be commingled
// and unretrievable under the owning tenant's scope.
//
// GetEntries(owner) authorizes and filters strictly by Entry.Owner, so a
// misattributed owner both leaks the telemetry into the wrong bucket and makes
// it invisible to the tenant that actually owns the provider.
func TestOpenClawTelemetryAttributedToOwningOrg(t *testing.T) {
	restore := withHermeticOrmer(t, new(Entry))
	defer restore()

	const tenantOrg = "acme"

	// A tenant-owned (organization-owned) OpenClaw agent provider.
	tenantProvider := &Provider{
		Owner:    tenantOrg,
		Name:     "openclaw-acme-regression",
		Category: "Log",
		Type:     "Agent",
		SubType:  "OpenClaw",
		Host:     "203.0.113.55",
		State:    "Enabled",
	}

	logProvider, err := GetLogProviderFromProvider(tenantProvider)
	if err != nil {
		t.Fatalf("GetLogProviderFromProvider returned error: %v", err)
	}

	openClaw, ok := logProvider.(*log.OpenClawProvider)
	if !ok {
		t.Fatalf("expected *log.OpenClawProvider, got %T", logProvider)
	}

	// Ingest one OTLP trace record through the tenant-owned provider, exactly as
	// the /api/v1/traces path does once a provider is resolved.
	if err = openClaw.AddTrace([]byte(`{"span":"regression"}`), "203.0.113.55", "regression-agent"); err != nil {
		t.Fatalf("AddTrace failed: %v", err)
	}

	// Positive control (healthy baseline): telemetry from the tenant-owned
	// provider MUST be retrievable under that tenant's own scope. This is the
	// legitimate request; if it is empty the whole test setup is broken rather
	// than the invariant, which keeps the red below provably about ownership.
	tenantEntries, err := GetEntries(tenantOrg)
	if err != nil {
		t.Fatalf("GetEntries(%q) failed: %v", tenantOrg, err)
	}
	tenantHit := findEntryByProvider(tenantEntries, tenantProvider.Name)

	// The invariant: telemetry MUST NOT be pooled into the global built-in org.
	builtinEntries, err := GetEntries(CasdoorOrganization)
	if err != nil {
		t.Fatalf("GetEntries(%q) failed: %v", CasdoorOrganization, err)
	}
	builtinHit := findEntryByProvider(builtinEntries, tenantProvider.Name)

	if builtinHit != nil {
		t.Errorf("tenant data-isolation violated: telemetry from tenant-owned provider %q was written under the global %q org (Entry.Owner=%q); it must be attributed to the owning org %q",
			tenantProvider.Name, CasdoorOrganization, builtinHit.Owner, tenantOrg)
	}

	if tenantHit == nil {
		t.Errorf("telemetry from tenant-owned provider %q is not retrievable under its owning org %q; it was misattributed away from the tenant scope",
			tenantProvider.Name, tenantOrg)
	} else if tenantHit.Owner != tenantOrg {
		t.Errorf("Entry.Owner = %q, want %q (the org that owns the provider)", tenantHit.Owner, tenantOrg)
	}
}

func findEntryByProvider(entries []*Entry, providerName string) *Entry {
	for _, e := range entries {
		if e.Provider == providerName {
			return e
		}
	}
	return nil
}
