// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"reflect"
	"testing"
)

// TestGetMaskedToken asserts the invariant behind TC-B03ABC19: a caller who is
// neither the token's owner nor a global admin (e.g. an org admin reading a
// different org member's token) must never receive the raw, replayable
// AccessToken/RefreshToken/Code values, while the owner and a global admin
// still get the real values back (so self-service and admin token
// inspection/revocation keep working).
func TestGetMaskedToken(t *testing.T) {
	rawToken := func() *Token {
		return &Token{
			Owner:        "admin",
			Name:         "7f24393d-3798-40a7-bdba-776ce387cdae",
			Application:  "app-niro-test",
			Organization: "niro-test",
			User:         "alice",
			Code:         "live-code-value",
			AccessToken:  "live-access-token-value",
			RefreshToken: "live-refresh-token-value",
			ExpiresIn:    604800,
			Scope:        "read",
		}
	}

	tests := []struct {
		name                 string
		isOwnerOrGlobalAdmin bool
		want                 *Token
	}{
		{
			name:                 "non-owner, non-global-admin (e.g. org admin reading another user's token) must have secrets redacted",
			isOwnerOrGlobalAdmin: false,
			want: &Token{
				Owner:        "admin",
				Name:         "7f24393d-3798-40a7-bdba-776ce387cdae",
				Application:  "app-niro-test",
				Organization: "niro-test",
				User:         "alice",
				Code:         "***",
				AccessToken:  "***",
				RefreshToken: "***",
				ExpiresIn:    604800,
				Scope:        "read",
			},
		},
		{
			name:                 "owner or global admin must still receive the real, usable token",
			isOwnerOrGlobalAdmin: true,
			want:                 rawToken(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMaskedToken(rawToken(), tt.isOwnerOrGlobalAdmin)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetMaskedToken() = %#v, want %#v", got, tt.want)
			}
			if !tt.isOwnerOrGlobalAdmin {
				if got.AccessToken == "live-access-token-value" {
					t.Fatal("GetMaskedToken() leaked the raw, replayable AccessToken to a non-owner, non-global-admin caller")
				}
				if got.RefreshToken == "live-refresh-token-value" {
					t.Fatal("GetMaskedToken() leaked the raw, replayable RefreshToken to a non-owner, non-global-admin caller")
				}
			}
		})
	}
}

// TestGetMaskedTokens asserts that listing endpoints (GetTokens /
// GetPaginationTokens) never return raw secrets, mirroring GetMaskedUsers'
// "lists always mask" policy: an org admin listing an entire org's tokens
// must not be able to harvest another user's live bearer credentials from
// the list response, regardless of the admin's own privilege level.
func TestGetMaskedTokens(t *testing.T) {
	tokens := []*Token{
		{Owner: "admin", Name: "t1", User: "alice", AccessToken: "alice-access", RefreshToken: "alice-refresh", Code: "alice-code"},
		{Owner: "admin", Name: "t2", User: "org-admin", AccessToken: "org-admin-access", RefreshToken: "org-admin-refresh", Code: "org-admin-code"},
	}
	want := []*Token{
		{Owner: "admin", Name: "t1", User: "alice", AccessToken: "***", RefreshToken: "***", Code: "***"},
		{Owner: "admin", Name: "t2", User: "org-admin", AccessToken: "***", RefreshToken: "***", Code: "***"},
	}

	got := GetMaskedTokens(tokens)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetMaskedTokens() = %#v, want %#v", got, want)
	}
}
