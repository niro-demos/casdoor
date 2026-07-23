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
	"sort"
	"strings"
	"testing"
)

// normalizeScope sorts the space-separated scope values so tests can compare
// scope sets regardless of ordering.
func normalizeScope(s string) string {
	fields := strings.Fields(s)
	sort.Strings(fields)
	return strings.Join(fields, " ")
}

// TestClampRefreshScope pins the security invariant for the OAuth refresh-token
// grant: refreshing a token must only ever PRESERVE or NARROW the scope that was
// originally granted (oldTokenScope). A client must never be able to widen scope
// by supplying an arbitrary `scope` form value to the refresh endpoint.
//
// This mirrors the black-box PoC for TC-D04F4537 (a refresh token granted
// "openid profile email offline_access" is redeemed while requesting
// "... superuser root sudo hacked_scope_xyz") but exercises the fix at its root
// cause: the pure scope-clamping helper that RefreshToken() applies before it
// signs the new token.
func TestClampRefreshScope(t *testing.T) {
	const granted = "openid profile email offline_access"

	// The built-in app has an EMPTY Scopes list, so IsScopeValidAndExpand alone
	// would wave any string through — this is exactly the config the finding
	// exploited. The clamp must still bound the requested scope to oldTokenScope.
	emptyScopesApp := &Application{Scopes: []*ScopeItem{}}

	// An app that DOES configure an allowlist, to prove the clamp also honors
	// IsScopeValidAndExpand and never widens past the granted scope even when a
	// value is allowlisted by the app.
	configuredApp := &Application{Scopes: []*ScopeItem{
		{Name: "openid"},
		{Name: "profile"},
		{Name: "email"},
		{Name: "offline_access"},
		{Name: "superuser"}, // allowlisted by the app, but NOT granted to this token
	}}

	tests := []struct {
		name          string
		requested     string
		oldTokenScope string
		application   *Application
		wantScope     string
		wantOK        bool
	}{
		{
			name:          "omitted scope defaults to granted scope",
			requested:     "",
			oldTokenScope: granted,
			application:   emptyScopesApp,
			wantScope:     granted,
			wantOK:        true,
		},
		{
			name:          "requesting exactly the granted scope is preserved",
			requested:     granted,
			oldTokenScope: granted,
			application:   emptyScopesApp,
			wantScope:     granted,
			wantOK:        true,
		},
		{
			name:          "narrowing to a subset is allowed",
			requested:     "openid email",
			oldTokenScope: granted,
			application:   emptyScopesApp,
			wantScope:     "openid email",
			wantOK:        true,
		},
		{
			// The core exploit: empty app Scopes must NOT let a client widen.
			name:          "widening on empty-Scopes app is rejected",
			requested:     granted + " superuser root sudo hacked_scope_xyz",
			oldTokenScope: granted,
			application:   emptyScopesApp,
			wantScope:     "",
			wantOK:        false,
		},
		{
			// Even a single unrelated extra value must be rejected.
			name:          "single ungranted value is rejected",
			requested:     "openid superuser",
			oldTokenScope: granted,
			application:   emptyScopesApp,
			wantScope:     "",
			wantOK:        false,
		},
		{
			// App allowlists "superuser", but this token was never granted it:
			// oldTokenScope intersection must still reject widening.
			name:          "app-allowlisted-but-ungranted value is rejected",
			requested:     "openid superuser",
			oldTokenScope: granted,
			application:   configuredApp,
			wantScope:     "",
			wantOK:        false,
		},
		{
			name:          "narrowing on configured app is allowed",
			requested:     "openid profile",
			oldTokenScope: granted,
			application:   configuredApp,
			wantScope:     "openid profile",
			wantOK:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScope, gotOK := clampRefreshScope(tt.requested, tt.oldTokenScope, tt.application)
			if gotOK != tt.wantOK {
				t.Fatalf("clampRefreshScope(%q, %q) ok = %v, want %v (scope=%q)",
					tt.requested, tt.oldTokenScope, gotOK, tt.wantOK, gotScope)
			}
			if tt.wantOK && normalizeScope(gotScope) != normalizeScope(tt.wantScope) {
				t.Fatalf("clampRefreshScope(%q, %q) scope = %q, want %q",
					tt.requested, tt.oldTokenScope, gotScope, tt.wantScope)
			}

			// Belt-and-suspenders on the accepted path: the returned scope must
			// never contain a value that was not in oldTokenScope. This is the
			// invariant the finding violates.
			if gotOK {
				grantedSet := map[string]bool{}
				for _, s := range strings.Fields(tt.oldTokenScope) {
					grantedSet[s] = true
				}
				for _, s := range strings.Fields(gotScope) {
					if !grantedSet[s] {
						t.Fatalf("INVARIANT VIOLATED: clampRefreshScope widened scope with %q "+
							"(granted=%q, got=%q)", s, tt.oldTokenScope, gotScope)
					}
				}
			}
		})
	}
}
