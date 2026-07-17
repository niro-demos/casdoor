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

import (
	"encoding/json"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestValidateSessionAndTokenListQueryRejectsUnsupportedFields(t *testing.T) {
	tests := []struct {
		name      string
		allowed   map[string]struct{}
		field     string
		value     string
		sortField string
		sortOrder string
		wantErr   bool
	}{
		{
			name:      "valid session query",
			allowed:   sessionListFields,
			field:     "name",
			value:     "alice",
			sortField: "createdTime",
			sortOrder: "ascend",
		},
		{
			name:      "valid token query",
			allowed:   tokenListFields,
			field:     "user",
			value:     "alice",
			sortField: "createdTime",
			sortOrder: "descend",
		},
		{
			name:      "invalid filter field",
			allowed:   sessionListFields,
			field:     "invalid",
			value:     "x",
			sortField: "createdTime",
			sortOrder: "ascend",
			wantErr:   true,
		},
		{
			name:      "invalid sort field",
			allowed:   tokenListFields,
			field:     "user",
			value:     "alice",
			sortField: "invalid",
			sortOrder: "ascend",
			wantErr:   true,
		},
		{
			name:      "invalid sort order",
			allowed:   tokenListFields,
			sortField: "createdTime",
			sortOrder: "asc",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListQuery(tt.field, tt.value, tt.sortField, tt.sortOrder, tt.allowed)
			if tt.wantErr && err == nil {
				t.Fatal("expected unsupported list parameter to be rejected")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected list parameters to be accepted, got %v", err)
			}
		})
	}
}

func TestPublicTokenProjectionOmitsCredentialFields(t *testing.T) {
	token := &object.Token{
		Owner:            "admin",
		Name:             "token-1",
		CreatedTime:      "2026-07-17T00:00:00Z",
		Application:      "app-acme",
		Organization:     "acme",
		User:             "alice",
		Code:             "authorization-code",
		AccessToken:      "access-token",
		RefreshToken:     "refresh-token",
		AccessTokenHash:  "access-hash",
		RefreshTokenHash: "refresh-hash",
		ExpiresIn:        3600,
		Scope:            "openid profile",
		TokenType:        "Bearer",
		GrantType:        "authorization_code",
		CodeChallenge:    "challenge",
		CodeIsUsed:       true,
		CodeExpireIn:     12345,
		Resource:         "https://api.example.test",
		DPoPJkt:          "thumbprint",
	}

	projected := getPublicToken(token)
	data, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}

	fields := map[string]any{}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}

	for _, secretField := range []string{"code", "accessToken", "refreshToken", "accessTokenHash", "refreshTokenHash"} {
		if _, ok := fields[secretField]; ok {
			t.Fatalf("projected token unexpectedly serialized %q: %s", secretField, string(data))
		}
	}
	for _, metadataField := range []string{"owner", "name", "organization", "user", "application", "expiresIn"} {
		if _, ok := fields[metadataField]; !ok {
			t.Fatalf("projected token omitted metadata field %q: %s", metadataField, string(data))
		}
	}
}

func TestPublicTokensProjectionOmitsCredentialFieldsFromLists(t *testing.T) {
	projected := getPublicTokens([]*object.Token{
		{
			Owner:            "admin",
			Name:             "token-1",
			Organization:     "acme",
			User:             "alice",
			AccessToken:      "access-token",
			RefreshToken:     "refresh-token",
			AccessTokenHash:  "access-hash",
			RefreshTokenHash: "refresh-hash",
			Code:             "authorization-code",
		},
	})

	data, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}

	var fields []map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 {
		t.Fatalf("projected %d tokens, want 1", len(fields))
	}

	for _, secretField := range []string{"code", "accessToken", "refreshToken", "accessTokenHash", "refreshTokenHash"} {
		if _, ok := fields[0][secretField]; ok {
			t.Fatalf("projected token list unexpectedly serialized %q: %s", secretField, string(data))
		}
	}
}
