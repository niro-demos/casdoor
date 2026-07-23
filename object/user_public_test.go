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

import "testing"

// sampleSensitiveUser builds a user carrying every category of sensitive data
// that must never reach an unauthorized caller via GET /api/get-user.
func sampleSensitiveUser() *User {
	return &User{
		Owner:                "org-beta",
		Name:                 "beta-user",
		DisplayName:          "Beta User",
		Avatar:               "https://example.com/a.png",
		Password:             "s3cret-hash",
		PasswordSalt:         "7166e79e6203272ca88f",
		PasswordType:         "bcrypt",
		Email:                "beta-user@niro.test",
		Phone:                "13100000004",
		IdCard:               "110101199003077777",
		AccessToken:          "at-xyz",
		OriginalToken:        "ot-xyz",
		OriginalRefreshToken: "rt-xyz",
		TotpSecret:           "totp-secret",
		RecoveryCodes:        []string{"rc-1", "rc-2"},
		MfaAccounts:          []MfaAccount{{SecretKey: "mfa-key"}},
		Score:                2000,
		Balance:              123.45,
	}
}

// TestGetMaskedUserClearsPasswordSalt is the regression test for defect (2):
// GetMaskedUser masked Password/tokens/MFA secrets but left PasswordSalt intact,
// so the bcrypt salt leaked on every masked/public response path.
//
// Invariant: a masked user must not carry the password salt (nor the password
// itself), regardless of whether the viewer is admin/self.
func TestGetMaskedUserClearsPasswordSalt(t *testing.T) {
	for _, isAdminOrSelf := range []bool{false, true} {
		user := sampleSensitiveUser()

		masked, err := GetMaskedUser(user, isAdminOrSelf)
		if err != nil {
			t.Fatalf("GetMaskedUser returned error: %v", err)
		}

		if masked.PasswordSalt != "" {
			t.Errorf("isAdminOrSelf=%v: PasswordSalt leaked through GetMaskedUser: %q (want cleared)", isAdminOrSelf, masked.PasswordSalt)
		}
		// Guard the existing invariant so this test also protects password masking.
		if masked.Password != "" && masked.Password != "***" {
			t.Errorf("isAdminOrSelf=%v: Password not masked: %q", isAdminOrSelf, masked.Password)
		}
	}
}

// TestGetPublicUserOmitsSensitiveFields is the regression test for defect (1):
// when an organization has IsProfilePublic=true the controller skipped
// authorization entirely and returned the FULL record to anyone. The fix routes
// unauthorized public-org reads through GetPublicUser, which must expose only a
// minimal, non-sensitive projection.
//
// Invariant: the public projection carries no credential material and no
// contactable PII (email/phone/idCard), and no financial fields — only safe,
// display-level identity fields.
func TestGetPublicUserOmitsSensitiveFields(t *testing.T) {
	pub := GetPublicUser(sampleSensitiveUser())
	if pub == nil {
		t.Fatal("GetPublicUser returned nil")
	}

	// Credential material — must never be present.
	if pub.Password != "" {
		t.Errorf("public projection leaked Password: %q", pub.Password)
	}
	if pub.PasswordSalt != "" {
		t.Errorf("public projection leaked PasswordSalt: %q", pub.PasswordSalt)
	}
	if pub.PasswordType != "" {
		t.Errorf("public projection leaked PasswordType: %q", pub.PasswordType)
	}
	if pub.AccessToken != "" || pub.OriginalToken != "" || pub.OriginalRefreshToken != "" {
		t.Errorf("public projection leaked token material: access=%q original=%q refresh=%q", pub.AccessToken, pub.OriginalToken, pub.OriginalRefreshToken)
	}
	if pub.TotpSecret != "" || len(pub.RecoveryCodes) != 0 || len(pub.MfaAccounts) != 0 {
		t.Errorf("public projection leaked MFA material: totp=%q recovery=%v mfa=%v", pub.TotpSecret, pub.RecoveryCodes, pub.MfaAccounts)
	}

	// Contactable PII — must never be present for an unauthorized caller.
	if pub.Email != "" {
		t.Errorf("public projection leaked Email: %q", pub.Email)
	}
	if pub.Phone != "" {
		t.Errorf("public projection leaked Phone: %q", pub.Phone)
	}
	if pub.IdCard != "" {
		t.Errorf("public projection leaked IdCard: %q", pub.IdCard)
	}

	// Financial fields — must not be present.
	if pub.Score != 0 || pub.Balance != 0 {
		t.Errorf("public projection leaked financial data: score=%d balance=%v", pub.Score, pub.Balance)
	}

	// Safe display-level identity must be preserved so the public profile is useful.
	if pub.Owner != "org-beta" || pub.Name != "beta-user" {
		t.Errorf("public projection dropped identity: owner=%q name=%q", pub.Owner, pub.Name)
	}
	if pub.DisplayName != "Beta User" {
		t.Errorf("public projection dropped DisplayName: %q", pub.DisplayName)
	}
}
