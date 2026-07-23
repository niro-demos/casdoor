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

// Invariant (RFC 7662 §2.1): a client application must NOT be able to use the
// token introspection endpoint to read the identity/scope/metadata of an access
// token that was issued to a *different* client application. Only the client the
// token was issued to (its owning application) may introspect it and receive
// active=true; any other authenticated caller must get active=false.
//
// IsIntrospectionCallerAuthorized encodes exactly that decision: it must be true
// only when the authenticated caller's client_id equals the client_id of the
// application the token was actually issued to.
func TestIsIntrospectionCallerAuthorized(t *testing.T) {
	const owner = "c5362661d924af8e68f9"   // app-beta (token's owning client)
	const nonOwner = "a511be8c40012169acdd" // app-built-in (a different client)

	tests := []struct {
		name              string
		callerClientId    string
		tokenOwnerClientId string
		want              bool
	}{
		{
			// The bug: a non-owning client that merely shares the signing cert
			// authenticates with its own valid credentials and introspects a
			// token issued to a different client. This MUST be rejected.
			name:               "non-owning client must not introspect another client's token",
			callerClientId:     nonOwner,
			tokenOwnerClientId: owner,
			want:               false,
		},
		{
			// Positive control: the owning client legitimately introspects its
			// own token and must be allowed — proving the check is specific to
			// ownership, not a blanket denial.
			name:               "owning client may introspect its own token",
			callerClientId:     owner,
			tokenOwnerClientId: owner,
			want:               true,
		},
		{
			// A missing/empty owner must never be treated as a match, otherwise
			// an empty caller id could slip through.
			name:               "empty owner is never authorized",
			callerClientId:     "",
			tokenOwnerClientId: "",
			want:               false,
		},
		{
			name:               "empty caller is never authorized against a real owner",
			callerClientId:     "",
			tokenOwnerClientId: owner,
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIntrospectionCallerAuthorized(tt.callerClientId, tt.tokenOwnerClientId)
			if got != tt.want {
				t.Fatalf("IsIntrospectionCallerAuthorized(caller=%q, owner=%q) = %v, want %v",
					tt.callerClientId, tt.tokenOwnerClientId, got, tt.want)
			}
		})
	}
}
