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

// IsIntrospectionCallerAuthorized reports whether an authenticated introspection
// caller is allowed to see the metadata of the token being introspected.
//
// Per RFC 7662 §2.1, the introspection endpoint must not disclose a token's
// identity/scope/metadata to a client the token was not issued to. The caller
// (already authenticated by client_id/client_secret) is authorized only when its
// client_id matches the client_id of the application the token was actually
// issued to. An empty client_id never matches, so a missing owner or an
// unauthenticated caller is always rejected.
func IsIntrospectionCallerAuthorized(callerClientId, tokenOwnerClientId string) bool {
	if callerClientId == "" || tokenOwnerClientId == "" {
		return false
	}
	return callerClientId == tokenOwnerClientId
}
