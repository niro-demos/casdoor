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

//go:build !skipCi

package object

import (
	"testing"
)

// Invariant under test (TC-71C31586): OAuth/OIDC access, ID, and refresh
// tokens (the default application.TokenFormat == "JWT" path) must never
// carry authentication secrets (password salt/type) or MFA/recovery seeds
// (TOTP secret, recovery codes), regardless of the scope the client
// requested. These fields have no OIDC/OAuth claim mapping and are never
// legitimate token content.
const (
	jwtSecretsTestOwner = "admin"
)

// setUpJwtSecretsTestApplication creates a minimal, isolated application
// (with its own real certificate) using the default JWT token format (the
// out-of-the-box behavior for every OAuth/OIDC application that doesn't
// override TokenFormat).
func setUpJwtSecretsTestApplication(t *testing.T, name string) *Application {
	t.Helper()
	InitConfig()

	certName := name + "-cert"
	certPem, keyPem, err := generateRsaKeys(1024, 256, 1, "jwt-secrets-test", "casdoor")
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	cert := &Cert{
		Owner:       jwtSecretsTestOwner,
		Name:        certName,
		Certificate: certPem,
		PrivateKey:  keyPem,
	}
	ok, err := AddCert(cert)
	if err != nil || !ok {
		t.Fatalf("failed to add test cert: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = DeleteCert(cert)
	})

	application := &Application{
		Owner:                name,
		Name:                 name,
		Organization:         "jwt-secrets-test-org",
		Cert:                 certName,
		ClientId:             name + "-client-id",
		ClientSecret:         name + "-client-secret",
		RedirectUris:         []string{"http://localhost:19001/callback"},
		ExpireInHours:        24,
		RefreshExpireInHours: 168,
		// TokenFormat left empty: generateJwtToken defaults this to "JWT",
		// which is what every application gets unless it explicitly opts
		// into JWT-Custom / JWT-Empty / JWT-Standard.
		TokenFormat: "",
	}
	ok, err = AddApplication(application)
	if err != nil || !ok {
		t.Fatalf("failed to add test application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = DeleteApplication(application)
	})

	return application
}

// TestGenerateJwtTokenExcludesAuthSecretsRegardlessOfScope is the red case
// for TC-71C31586: a user with TOTP MFA enabled who completes an OAuth flow
// requesting only the narrowest scope ("openid") must not get their
// password salt/type, TOTP seed, or recovery codes embedded in the
// access token, ID token (which reuses the access token string), or
// refresh token.
func TestGenerateJwtTokenExcludesAuthSecretsRegardlessOfScope(t *testing.T) {
	application := setUpJwtSecretsTestApplication(t, "test-jwt-secrets-app")

	user := &User{
		Owner:         jwtSecretsTestOwner,
		Name:          "alice",
		Id:            "alice-id",
		Email:         "alice@example.test",
		Phone:         "15555550101",
		DisplayName:   "Alice",
		Password:      "should-never-appear-either",
		PasswordSalt:  "bb99b83d09194ee5e595",
		PasswordType:  "bcrypt",
		TotpSecret:    "PCQUWEQWMSX6UUMBRG5273YKNLVSXI6E",
		RecoveryCodes: []string{"02780bb4-4319-49ed-87f5-e4cfbf65e976"},
	}

	accessToken, refreshToken, _, err := generateJwtToken(application, user, "", "", "", "openid", "", "localhost:8000")
	if err != nil {
		t.Fatalf("generateJwtToken returned an error: %v", err)
	}

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"access_token / id_token", accessToken},
		{"refresh_token", refreshToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseJwtTokenWithoutValidation(tc.token)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", tc.name, err)
			}
			claims, ok := parsed.Claims.(*Claims)
			if !ok || claims.User == nil {
				t.Fatalf("%s did not decode into expected claims shape", tc.name)
			}

			// The invariant: these secrets must never be present, no
			// matter what scope was requested.
			if claims.User.Password != "" {
				t.Errorf("%s leaks Password: %q", tc.name, claims.User.Password)
			}
			if claims.User.PasswordSalt != "" {
				t.Errorf("%s leaks PasswordSalt: %q", tc.name, claims.User.PasswordSalt)
			}
			if claims.User.PasswordType != "" {
				t.Errorf("%s leaks PasswordType: %q", tc.name, claims.User.PasswordType)
			}
			if claims.User.TotpSecret != "" {
				t.Errorf("%s leaks TotpSecret: %q", tc.name, claims.User.TotpSecret)
			}
			if len(claims.User.RecoveryCodes) != 0 {
				t.Errorf("%s leaks RecoveryCodes: %v", tc.name, claims.User.RecoveryCodes)
			}

			// Control: the token must still identify the user correctly,
			// proving the fix strips secrets without breaking normal
			// token issuance.
			if claims.User.Id != user.Id {
				t.Errorf("%s: Id = %q, want %q (token issuance itself must keep working)", tc.name, claims.User.Id, user.Id)
			}
			if claims.User.Email != user.Email {
				t.Errorf("%s: Email = %q, want %q (non-secret claims must be unaffected)", tc.name, claims.User.Email, user.Email)
			}
		})
	}
}
