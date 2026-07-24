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

	"github.com/xorm-io/xorm"
	_ "modernc.org/sqlite"
)

// Security regression test for the cross-tenant audit-log leak on
// GET /api/get-records (no pagination params).
//
// Invariant: an organization-scoped fetch of audit records must only ever
// return records belonging to that organization, never records from other
// tenants. The controller's no-params branch used to call GetRecords()
// (unfiltered), leaking every tenant's audit trail to an org-scoped admin.
//
// This test is fully hermetic: it stands up its own isolated in-memory sqlite
// engine, seeds Record rows across several organizations, and exercises the
// real object-layer fetch. It never touches the configured/running database.

// newIsolatedRecordEngine builds a throwaway in-memory sqlite engine, points
// the package-global ormer at it, and syncs the Record table. It returns a
// cleanup func that restores the previous ormer and closes the engine.
func newIsolatedRecordEngine(t *testing.T) func() {
	t.Helper()

	// A private DSN name gives each test its own isolated in-memory database.
	engine, err := xorm.NewEngine("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite engine: %v", err)
	}
	if err := engine.Sync2(new(Record)); err != nil {
		_ = engine.Close()
		t.Fatalf("failed to sync Record table: %v", err)
	}

	prev := ormer
	ormer = &Ormer{Engine: engine}

	return func() {
		ormer = prev
		_ = engine.Close()
	}
}

func seedRecord(t *testing.T, org, user string) {
	t.Helper()
	rec := &Record{
		Owner:        org,
		Name:         org + "-" + user,
		Organization: org,
		User:         user,
		Action:       "login",
		Method:       "POST",
		RequestUri:   "/api/login",
		Object:       `{"organization":"` + org + `","username":"` + user + `","password":"secret"}`,
	}
	if _, err := ormer.Engine.Insert(rec); err != nil {
		t.Fatalf("failed to seed record for org %q: %v", org, err)
	}
}

// TestGetRecordsByOrganization_TenantIsolation asserts the core invariant: an
// org-scoped fetch of audit records returns ONLY that org's records. This is
// the path the controller must take on the no-params branch for a non-global
// admin.
//
// RED (before the fix): the no-params branch called the unfiltered GetRecords(),
// so an acme-scoped admin received every tenant's records — this assertion fails.
// GREEN (after the fix): GetRecordsByOrganization("acme") returns only acme.
func TestGetRecordsByOrganization_TenantIsolation(t *testing.T) {
	cleanup := newIsolatedRecordEngine(t)
	defer cleanup()

	// Seed audit records across four distinct tenants.
	seedRecord(t, "acme", "alice")
	seedRecord(t, "acme", "bob")
	seedRecord(t, "globex", "carol")
	seedRecord(t, "built-in", "admin")
	seedRecord(t, "anonymous", "guest")

	// Positive control: a global-admin / all-orgs fetch legitimately sees
	// every tenant. This proves the seed data and engine are healthy, so any
	// isolation failure below is the invariant, not a broken setup.
	all, err := GetRecords()
	if err != nil {
		t.Fatalf("GetRecords() failed: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("control: expected 5 seeded records across all orgs, got %d", len(all))
	}

	// The invariant under test: an acme-scoped admin must see only acme records.
	scoped, err := GetRecordsByOrganization("acme")
	if err != nil {
		t.Fatalf("GetRecordsByOrganization(\"acme\") failed: %v", err)
	}

	if len(scoped) != 2 {
		t.Fatalf("tenant isolation VIOLATED: acme-scoped fetch returned %d records, want 2 (acme/alice, acme/bob)", len(scoped))
	}
	for _, rec := range scoped {
		if rec.Organization != "acme" {
			t.Errorf("tenant isolation VIOLATED: acme-scoped fetch leaked a record from organization %q (user %q)", rec.Organization, rec.User)
		}
	}
}

// TestGetRecordsByOrganization_EmptyMeansAll documents that the empty
// organization sentinel (used only for a true global admin, owner=="built-in")
// widens the fetch to all tenants — the same semantics the controller relies on
// after computing organization="" for a genuine global admin.
func TestGetRecordsByOrganization_EmptyMeansAll(t *testing.T) {
	cleanup := newIsolatedRecordEngine(t)
	defer cleanup()

	seedRecord(t, "acme", "alice")
	seedRecord(t, "globex", "carol")

	scoped, err := GetRecordsByOrganization("")
	if err != nil {
		t.Fatalf("GetRecordsByOrganization(\"\") failed: %v", err)
	}
	if len(scoped) != 2 {
		t.Fatalf("global-admin (empty org) fetch should return all %d records, got %d", 2, len(scoped))
	}
}
