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
	"fmt"
	"path/filepath"
	"testing"
)

// initWebFingerTestDB spins up an isolated, empty sqlite database for the
// test (via env-var overrides that conf.GetConfigString() prefers over
// conf/app.conf, the same mechanism niro/harness/start.sh uses) so this test
// never touches a real/shared MySQL instance and cleans up automatically.
func initWebFingerTestDB(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "webfinger_test.db")
	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", fmt.Sprintf("file:%s?cache=shared", dbFile))
	t.Setenv("dbName", "casdoor")

	// sqlite has no "CREATE DATABASE" statement (unlike the mysql/postgres
	// drivers other object package tests run against); skip that step, the
	// same way niro/harness/start.sh's sqlite-backed server does by leaving
	// the --createDatabase flag at its false default. createTable() (called
	// below by InitConfig -> CreateTables) still runs and works fine on
	// sqlite via xorm's Sync2.
	oldCreateDatabase := createDatabase
	createDatabase = false
	t.Cleanup(func() { createDatabase = oldCreateDatabase })

	InitConfig()
}

// TestGetWebFingerDoesNotLeakAccountExistence is the regression test for
// TC-52D52F22: the unauthenticated /.well-known/webfinger endpoint must not
// let a caller distinguish a registered account from a fabricated one via
// the response shape (error vs. success) returned by object.GetWebFinger.
func TestGetWebFingerDoesNotLeakAccountExistence(t *testing.T) {
	initWebFingerTestDB(t)

	const owner = "acme"
	const email = "bob@acme.example.com"

	registeredUser := &User{
		Owner:       owner,
		Name:        "bob",
		Id:          "webfinger-test-bob",
		Email:       email,
		CreatedTime: "2026-01-01T00:00:00Z",
	}
	if _, err := ormer.Engine.Insert(registeredUser); err != nil {
		t.Fatalf("failed to seed registered user fixture: %v", err)
	}

	rels := []string{"http://openid.net/specs/connect/1.0/issuer"}

	// Positive control: a known-registered account must resolve
	// successfully, otherwise this isn't a valid comparison.
	wfExisting, errExisting := GetWebFinger("acct:"+email, rels, "localhost:8000", "")
	if errExisting != nil {
		t.Fatalf("expected no error for registered account %q, got: %v", email, errExisting)
	}
	if wfExisting.Subject != "acct:"+email {
		t.Fatalf("expected subject %q for registered account, got %q", "acct:"+email, wfExisting.Subject)
	}

	// The account under test: guaranteed not to exist in this fresh,
	// isolated database.
	fakeEmail := "niro-verify-nonexistent-user@acme.example.com"
	wfFake, errFake := GetWebFinger("acct:"+fakeEmail, rels, "localhost:8000", "")

	// Invariant under test: the response for a fabricated identity must be
	// indistinguishable (same error/success shape) from a registered one, so
	// account existence cannot be inferred from the response.
	if (errExisting == nil) != (errFake == nil) {
		t.Fatalf("account existence is distinguishable via error presence: registered err=%v, fabricated err=%v", errExisting, errFake)
	}
	if errFake != nil {
		// Both errored identically (e.g. a hard DB failure) -- not an
		// enumeration signal, nothing further to compare.
		return
	}
	if wfFake.Subject != "acct:"+fakeEmail {
		t.Fatalf("expected subject %q for fabricated account (same shape as a registered one), got %q", "acct:"+fakeEmail, wfFake.Subject)
	}
}
