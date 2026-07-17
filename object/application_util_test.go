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
	"testing"
)

func TestRedirectUriMatchesPattern(t *testing.T) {
	tests := []struct {
		redirectUri string
		targetUri   string
		want        bool
	}{
		// Exact match
		{"https://login.example.com/callback", "https://login.example.com/callback", true},

		// Full URL pattern: exact host
		{"https://login.example.com/callback", "https://login.example.com/callback", true},
		{"https://login.example.com/other", "https://login.example.com/callback", false},

		// Full URL pattern: subdomain of configured host
		{"https://def.abc.com/callback", "abc.com", true},
		{"https://def.abc.com/callback", ".abc.com", true},
		{"https://def.abc.com/callback", ".abc.com/", true},
		{"https://deep.app.example.com/callback", "https://example.com/callback", true},

		// Full URL pattern: unrelated host must not match
		{"https://evil.com/callback", "https://example.com/callback", false},
		// Suffix collision: evilexample.com must not match example.com
		{"https://evilexample.com/callback", "https://example.com/callback", false},

		// Full URL pattern: scheme mismatch
		{"http://app.example.com/callback", "https://example.com/callback", false},

		// Full URL pattern: path mismatch
		{"https://app.example.com/other", "https://example.com/callback", false},

		// Scheme-less pattern: exact host
		{"https://login.example.com/callback", "login.example.com/callback", true},
		{"http://login.example.com/callback", "login.example.com/callback", true},

		// Scheme-less pattern: subdomain of configured host
		{"https://app.login.example.com/callback", "login.example.com/callback", true},

		// Scheme-less pattern: unrelated host must not match
		{"https://evil.com/callback", "login.example.com/callback", false},

		// Scheme-less pattern: query-string injection must not match
		{"https://evil.com/?r=https://login.example.com/callback", "login.example.com/callback", false},
		{"https://evil.com/page?redirect=https://login.example.com/callback", "login.example.com/callback", false},

		// Scheme-less pattern: path mismatch
		{"https://login.example.com/other", "login.example.com/callback", false},

		// Scheme-less pattern: non-http scheme must not match
		{"ftp://login.example.com/callback", "login.example.com/callback", false},

		// Empty target
		{"https://login.example.com/callback", "", false},
	}

	for _, tt := range tests {
		got := redirectUriMatchesPattern(tt.redirectUri, tt.targetUri)
		if got != tt.want {
			t.Errorf("redirectUriMatchesPattern(%q, %q) = %v, want %v", tt.redirectUri, tt.targetUri, got, tt.want)
		}
	}
}

// TestFilterApplicationsForOrgAdmin covers the pure decision behind
// filterApplicationsForOrgAdmin (object/application_util.go), the
// root-cause fix for TC-44A41C6A: GetAllowedApplications special-cased
// user.IsAdmin and returned every application in the requested organization
// without checking that the caller's Owner matched that organization (or
// application.IsShared).
func TestFilterApplicationsForOrgAdmin(t *testing.T) {
	orgScopedAdmin := &User{Owner: "acme", Name: "acme-admin", IsAdmin: true}

	ownOrgApp := &Application{Owner: "admin", Name: "app-acme", Organization: "acme"}
	otherOrgApp := &Application{Owner: "admin", Name: "app-built-in", Organization: "built-in"}
	sharedApp := &Application{Owner: "admin", Name: "app-shared", Organization: "built-in", IsShared: true}

	t.Run("own org applications are returned", func(t *testing.T) {
		got, err := filterApplicationsForOrgAdmin(orgScopedAdmin, []*Application{ownOrgApp}, "en")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != ownOrgApp {
			t.Fatalf("filterApplicationsForOrgAdmin() = %v, want [ownOrgApp]", got)
		}
	})

	t.Run("shared applications from another org are returned", func(t *testing.T) {
		got, err := filterApplicationsForOrgAdmin(orgScopedAdmin, []*Application{sharedApp}, "en")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != sharedApp {
			t.Fatalf("filterApplicationsForOrgAdmin() = %v, want [sharedApp]", got)
		}
	})

	t.Run("another org's non-shared applications are denied, not filtered to empty", func(t *testing.T) {
		got, err := filterApplicationsForOrgAdmin(orgScopedAdmin, []*Application{otherOrgApp}, "en")
		if err == nil {
			t.Fatalf("expected an authorization error, got applications: %v", got)
		}
		if !strings.Contains(err.Error(), "Unauthorized") {
			t.Fatalf("expected an \"Unauthorized operation\" error, got: %v", err)
		}
		if got != nil {
			t.Fatalf("expected no applications on denial, got: %v", got)
		}
	})
}
