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

import "testing"

// TestIsIntrospectionAuthorized asserts the tenant-isolation invariant for the
// OAuth token introspection endpoint (RFC 7662): a client may only introspect a
// token it owns (its own client_id is the token's owning client_id, or it appears
// in the token's aud). A client from a different tenant/application MUST NOT be
// authorized to introspect a foreign token, so the endpoint returns
// {"active": false} rather than leaking the token owner's username/sub/scope.
//
// Scenario mirrors PoC TC-6607AF88: app-acme (client_id ef2d...) issues a token
// for user alice with aud=[ef2d...]; the unrelated app-globex client (client_id
// 988e...) must be denied.
func TestIsIntrospectionAuthorized(t *testing.T) {
	const (
		acmeClientId   = "ef2d8c3f326775949f4f" // token's owning application (tenant acme)
		globexClientId = "988eeee4155f2a7a00f7" // unrelated caller (tenant globex)
	)
	tokenAud := []string{acmeClientId}

	tests := []struct {
		name                string
		callerClientId      string
		tokenOwningClientId string
		tokenAudience       []string
		want                bool
	}{
		{
			// Positive control: the owning client introspects its OWN token.
			// Proves the gate does not break the legitimate flow (green baseline),
			// so the cross-tenant red below is the invariant, not a broken setup.
			name:                "owning client may introspect its own token",
			callerClientId:      acmeClientId,
			tokenOwningClientId: acmeClientId,
			tokenAudience:       tokenAud,
			want:                true,
		},
		{
			// Exploit: unrelated cross-tenant client introspects the acme token.
			// Before the fix the endpoint returned active=true with alice's
			// identity/scope; the invariant requires this to be denied.
			name:                "cross-tenant client must NOT introspect a foreign token",
			callerClientId:      globexClientId,
			tokenOwningClientId: acmeClientId,
			tokenAudience:       tokenAud,
			want:                false,
		},
		{
			// A client explicitly listed in the token's audience is authorized,
			// even if it is not the token's owning application (RFC 8693 audience).
			name:                "client in token audience is authorized",
			callerClientId:      globexClientId,
			tokenOwningClientId: acmeClientId,
			tokenAudience:       []string{acmeClientId, globexClientId},
			want:                true,
		},
		{
			// Fail closed on an unauthenticated / empty caller.
			name:                "empty caller client_id is denied",
			callerClientId:      "",
			tokenOwningClientId: acmeClientId,
			tokenAudience:       tokenAud,
			want:                false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIntrospectionAuthorized(tt.callerClientId, tt.tokenOwningClientId, tt.tokenAudience)
			if got != tt.want {
				t.Fatalf("IsIntrospectionAuthorized(caller=%q, owner=%q, aud=%v) = %v, want %v",
					tt.callerClientId, tt.tokenOwningClientId, tt.tokenAudience, got, tt.want)
			}
		})
	}
}
