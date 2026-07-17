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
	"encoding/json"
	"testing"
)

// mfaLeakTestUser builds a *User carrying the credential-recovery fields that
// must never reach an issued OAuth token, mirroring an account with app TOTP
// MFA enabled (as in TC-C39E51EF).
func mfaLeakTestUser() *User {
	return &User{
		Owner:            "built-in",
		Name:             "admin",
		Id:               "built-in/admin",
		Password:         "should-never-leak",
		PasswordSalt:     "test-password-salt-value",
		PasswordType:     "bcrypt",
		Email:            "admin@example.com",
		PreferredMfaType: "app",
		TotpSecret:       "TESTSECRETNOTAREALSEEDVALUEXXXXX",
		RecoveryCodes:    []string{"test-recovery-code-0000-0000"},
		MfaPhoneEnabled:  true,
		MfaEmailEnabled:  true,
	}
}

// leakedFields are the JSON keys that must never appear in an issued
// access_token / id_token / refresh_token payload, per the invariant from
// TC-C39E51EF: OAuth tokens must not contain the user's TOTP MFA secret,
// password-reset recovery codes, or password hash metadata.
var leakedFields = []string{
	"totpSecret",
	"recoveryCodes",
	"passwordSalt",
	"passwordType",
	"password",
	"preferredMfaType",
}

// assertNoLeakedFields marshals v exactly like the JWT library would (both
// jwt.NewWithClaims and json.Marshal use encoding/json under the hood) and
// checks that none of the credential-recovery keys are present in the
// resulting JSON object - the same shape of check the PoC performs on the
// decoded token payload.
func assertNoLeakedFields(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}

	for _, field := range leakedFields {
		if val, present := decoded[field]; present {
			t.Errorf("%q must not be present in issued tokens, got %v", field, val)
		}
	}

	return decoded
}

// TestGetUserWithoutThirdIdpExcludesCredentialRecoverySecrets asserts the
// invariant from TC-C39E51EF: the struct that is serialized verbatim into
// access_token / id_token / refresh_token for TokenFormat "JWT" must never
// carry the user's TOTP secret, MFA recovery codes, or password-hash
// metadata. getUserWithoutThirdIdp is the shared function that builds that
// payload for all three token types (see getClaimsWithoutThirdIdp), so
// fixing it here closes the leak everywhere it is used.
func TestGetUserWithoutThirdIdpExcludesCredentialRecoverySecrets(t *testing.T) {
	user := mfaLeakTestUser()

	res := getUserWithoutThirdIdp(user)
	decoded := assertNoLeakedFields(t, res)

	// Control: ordinary profile fields the openid/profile scope legitimately
	// needs must still come through unchanged - proves this is a targeted
	// redaction, not a broken/empty struct.
	if decoded["email"] != user.Email {
		t.Errorf("expected profile field email to survive redaction, got %v want %q", decoded["email"], user.Email)
	}
	if decoded["name"] != user.Name {
		t.Errorf("expected profile field name to survive redaction, got %v want %q", decoded["name"], user.Name)
	}
}

// TestGetClaimsWithoutThirdIdpExcludesCredentialRecoverySecrets exercises the
// same invariant one layer up, through getClaimsWithoutThirdIdp - the exact
// function generateJwtToken calls to build the payload for the default
// TokenFormat "JWT" access_token/id_token/refresh_token.
func TestGetClaimsWithoutThirdIdpExcludesCredentialRecoverySecrets(t *testing.T) {
	user := mfaLeakTestUser()
	claims := Claims{
		User:      user,
		TokenType: "access-token",
		Scope:     "openid profile",
	}

	res := getClaimsWithoutThirdIdp(claims)
	assertNoLeakedFields(t, res)
}
