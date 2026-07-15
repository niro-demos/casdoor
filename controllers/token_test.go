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

package controllers

import "testing"

// TestTokenIssuedToClient asserts the RFC 7662 client-ownership invariant
// that IntrospectToken relies on: a client may only introspect (see the
// active status, identity and metadata of) a token that was actually issued
// to it. Modeled directly on TC-92B83652: alice's access token was issued to
// app-acme (client_id 89b64c2155a54b7ab450); app-built-in (client_id
// 81b3a52f71271b58f22c) is a completely different, unrelated application
// that the token was never issued to.
func TestTokenIssuedToClient(t *testing.T) {
	const (
		appAcmeClientId    = "89b64c2155a54b7ab450" // token's actual owning application (app-acme, org acme)
		appBuiltInClientId = "81b3a52f71271b58f22c" // unrelated application (app-built-in, org built-in)
	)

	tests := []struct {
		name               string
		tokenOwnerClientId string
		requestClientId    string
		want               bool
	}{
		{
			name:               "legitimate owner introspecting its own token is allowed",
			tokenOwnerClientId: appAcmeClientId,
			requestClientId:    appAcmeClientId,
			want:               true,
		},
		{
			name:               "unrelated application introspecting a token issued to a different application must be denied",
			tokenOwnerClientId: appAcmeClientId,
			requestClientId:    appBuiltInClientId,
			want:               false,
		},
		{
			name:               "empty token owner client id (unresolved application) must be denied",
			tokenOwnerClientId: "",
			requestClientId:    appAcmeClientId,
			want:               false,
		},
		{
			name:               "empty request client id must be denied",
			tokenOwnerClientId: appAcmeClientId,
			requestClientId:    "",
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenIssuedToClient(tt.tokenOwnerClientId, tt.requestClientId)
			if got != tt.want {
				t.Fatalf("tokenIssuedToClient(%q, %q) = %v, want %v — an OAuth client must not be able to introspect a token issued to a different, unrelated application",
					tt.tokenOwnerClientId, tt.requestClientId, got, tt.want)
			}
		})
	}
}
