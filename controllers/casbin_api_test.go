// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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

// TestResolveCasbinApiUserId locks in the authorization invariant for the
// Casbin-API style lookup endpoints (GetAllObjects/GetAllActions/GetAllRoles):
// anonymous, unauthenticated callers, and authenticated callers who are
// neither the target user nor an admin, must never be handed another user's
// roles/objects/actions by supplying an arbitrary ?userId=owner/name value.
func TestResolveCasbinApiUserId(t *testing.T) {
	tests := []struct {
		name           string
		sessionUserId  string
		queryUserId    string
		isAdmin        bool
		wantUserId     string
		wantAuthorized bool
	}{
		{
			name:           "anonymous caller requesting another user's data is rejected",
			sessionUserId:  "",
			queryUserId:    "acme/alice",
			isAdmin:        false,
			wantUserId:     "",
			wantAuthorized: false,
		},
		{
			name:           "anonymous caller with no userId at all is rejected",
			sessionUserId:  "",
			queryUserId:    "",
			isAdmin:        false,
			wantUserId:     "",
			wantAuthorized: false,
		},
		{
			name:           "authenticated non-admin querying another user's data is rejected",
			sessionUserId:  "acme/bob",
			queryUserId:    "acme/alice",
			isAdmin:        false,
			wantUserId:     "",
			wantAuthorized: false,
		},
		{
			name:           "authenticated caller with no userId falls back to session self-lookup",
			sessionUserId:  "acme/alice",
			queryUserId:    "",
			isAdmin:        false,
			wantUserId:     "acme/alice",
			wantAuthorized: true,
		},
		{
			name:           "authenticated caller explicitly querying their own userId is allowed",
			sessionUserId:  "acme/alice",
			queryUserId:    "acme/alice",
			isAdmin:        false,
			wantUserId:     "acme/alice",
			wantAuthorized: true,
		},
		{
			name:           "admin querying another user's data is allowed",
			sessionUserId:  "built-in/admin",
			queryUserId:    "acme/alice",
			isAdmin:        true,
			wantUserId:     "acme/alice",
			wantAuthorized: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserId, gotAuthorized := resolveCasbinApiUserId(tt.sessionUserId, tt.queryUserId, tt.isAdmin)
			if gotAuthorized != tt.wantAuthorized {
				t.Fatalf("resolveCasbinApiUserId(%q, %q, %v) authorized = %v, want %v",
					tt.sessionUserId, tt.queryUserId, tt.isAdmin, gotAuthorized, tt.wantAuthorized)
			}
			if gotAuthorized && gotUserId != tt.wantUserId {
				t.Fatalf("resolveCasbinApiUserId(%q, %q, %v) userId = %q, want %q",
					tt.sessionUserId, tt.queryUserId, tt.isAdmin, gotUserId, tt.wantUserId)
			}
		})
	}
}
