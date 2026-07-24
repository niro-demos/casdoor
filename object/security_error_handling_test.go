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
	"sync"
	"testing"
)

var initSecurityErrorHandlingTestDatabaseOnce sync.Once

func TestSendEmailRejectsNilProvider(t *testing.T) {
	assertNoPanic(t, func() {
		err := SendEmail(nil, "title", "content", []string{"nobody@example.invalid"}, "noreply@example.invalid")
		if err == nil {
			t.Fatal("SendEmail(nil) error = nil, want controlled provider error")
		}
		assertNoDiagnosticLeak(t, err.Error())
	})
}

func TestGenerateSamlRequestRejectsMissingProvider(t *testing.T) {
	initSecurityErrorHandlingTestDatabase(t)

	assertNoPanic(t, func() {
		_, _, err := GenerateSamlRequest("niro-test/no-such-provider-928374", "", "http://example.com", "en")
		if err == nil {
			t.Fatal("GenerateSamlRequest() error = nil, want controlled missing-provider error")
		}
		assertNoDiagnosticLeak(t, err.Error())
	})
}

func TestSyncLdapUsersRejectsMissingLdap(t *testing.T) {
	initSecurityErrorHandlingTestDatabase(t)

	assertNoPanic(t, func() {
		_, _, err := SyncLdapUsers("built-in", nil, "bad/id")
		if err == nil {
			t.Fatal("SyncLdapUsers() error = nil, want controlled missing-LDAP error")
		}
		assertNoDiagnosticLeak(t, err.Error())
	})
}

func initSecurityErrorHandlingTestDatabase(t *testing.T) {
	t.Helper()

	initSecurityErrorHandlingTestDatabaseOnce.Do(func() {
		t.Setenv("driverName", "sqlite")
		t.Setenv("dataSourceName", "file:casdoor-security-error-handling?mode=memory&cache=shared")
		t.Setenv("dbName", "")
		createDatabase = false
		InitConfig()

		_, err := ormer.Engine.Insert(&Organization{Owner: "admin", Name: "built-in"})
		if err != nil {
			t.Fatalf("seed built-in organization: %v", err)
		}
	})
}

func assertNoPanic(t *testing.T, fn func()) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic instead of controlled error: %v", r)
		}
	}()

	fn()
}

func assertNoDiagnosticLeak(t *testing.T, text string) {
	t.Helper()

	leakMarkers := []string{
		"runtime error",
		"invalid memory address",
		"panic",
		"/go/src/casdoor/",
		"/usr/local/go/src/runtime/",
	}
	for _, marker := range leakMarkers {
		if strings.Contains(text, marker) {
			t.Fatalf("error %q contains diagnostic marker %q", text, marker)
		}
	}
}
