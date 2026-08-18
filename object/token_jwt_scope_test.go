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
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJwtClaimsRespectOAuthScopes(t *testing.T) {
	user := &User{
		Id:               "subject-id",
		Name:             "alice",
		DisplayName:      "Alice Example",
		Email:            "alice@example.com",
		Phone:            "15555550101",
		Affiliation:      "Private affiliation",
		CreatedIp:        "192.0.2.1",
		PasswordSalt:     "secret-salt",
		PasswordType:     "bcrypt",
		SigninWrongTimes: 3,
		IsAdmin:          true,
		IsForbidden:      true,
	}

	openidClaims := jwtClaimsAsMap(t, getClaimsWithoutThirdIdp(Claims{
		User:  user,
		Scope: "openid",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: user.Id,
		},
	}))
	if openidClaims["sub"] != user.Id {
		t.Fatalf("openid token subject = %v, want %q", openidClaims["sub"], user.Id)
	}
	for _, field := range []string{"email", "phone", "affiliation", "createdIp", "passwordSalt", "passwordType", "signinWrongTimes", "isAdmin", "isForbidden"} {
		if value, ok := openidClaims[field]; ok {
			t.Errorf("openid-only token disclosed %s (%v)", field, value)
		}
	}

	emailClaims := jwtClaimsAsMap(t, getClaimsWithoutThirdIdp(Claims{
		User:  user,
		Scope: "openid email",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: user.Id,
		},
	}))
	if emailClaims["email"] != user.Email {
		t.Errorf("email-scoped token email = %v, want %q", emailClaims["email"], user.Email)
	}
	for _, field := range []string{"passwordSalt", "passwordType", "createdIp", "signinWrongTimes", "isAdmin", "isForbidden"} {
		if value, ok := emailClaims[field]; ok {
			t.Errorf("email-scoped token disclosed sensitive field %s (%v)", field, value)
		}
	}

	whitelistedClaims := jwtClaimsAsMap(t, getClaimsWithoutThirdIdp(Claims{
		User:  user,
		Scope: "openid profile email phone",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: user.Id,
		},
	}, []string{"Email"}))
	if whitelistedClaims["email"] != user.Email {
		t.Errorf("whitelisted email = %v, want %q", whitelistedClaims["email"], user.Email)
	}
	for _, field := range []string{"name", "preferred_username", "phone"} {
		if value, ok := whitelistedClaims[field]; ok {
			t.Errorf("token field allowlist did not exclude %s (%v)", field, value)
		}
	}
}

func jwtClaimsAsMap(t *testing.T, claims any) map[string]any {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err = json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
