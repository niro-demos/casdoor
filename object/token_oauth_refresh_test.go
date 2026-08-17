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

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

// setupRefreshTokenFixtures creates a throwaway organization, signing cert,
// confidential OAuth application and user directly through the DB adapter so
// TestRefreshToken* can exercise object.RefreshToken end to end without
// depending on any externally-seeded environment. Everything created here is
// removed via t.Cleanup.
func setupRefreshTokenFixtures(t *testing.T) (*Application, *User) {
	t.Helper()

	suffix := util.GenerateId()
	orgName := "org-refresh-" + suffix
	certName := "cert-refresh-" + suffix
	appName := "app-refresh-" + suffix
	userName := "user-refresh-" + suffix

	certificate, privateKey, err := generateRsaKeys(2048, 256, 1, certName, orgName)
	if err != nil {
		t.Fatalf("failed to generate test signing cert: %v", err)
	}

	cert := &Cert{
		Owner:           "admin",
		Name:            certName,
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     "Refresh Token Test Cert",
		Scope:           "JWT",
		Type:            "x509",
		CryptoAlgorithm: "RS256",
		BitSize:         2048,
		ExpireInYears:   1,
		Certificate:     certificate,
		PrivateKey:      privateKey,
	}
	if _, err := ormer.Engine.Insert(cert); err != nil {
		t.Fatalf("failed to insert test cert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.ID(core.PK{cert.Owner, cert.Name}).Delete(&Cert{})
	})

	org := &Organization{
		Owner:       "admin",
		Name:        orgName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Refresh Token Test Org",
	}
	if _, err := ormer.Engine.Insert(org); err != nil {
		t.Fatalf("failed to insert test organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.ID(core.PK{org.Owner, org.Name}).Delete(&Organization{})
	})

	application := &Application{
		Owner:                "admin",
		Name:                 appName,
		CreatedTime:          util.GetCurrentTime(),
		DisplayName:          "Refresh Token Test App (confidential)",
		Organization:         orgName,
		Cert:                 certName,
		ClientId:             "client-" + suffix,
		ClientSecret:         "correct-secret-" + suffix,
		RedirectUris:         []string{"http://localhost:19001/callback"},
		GrantTypes:           []string{"authorization_code", "refresh_token"},
		TokenFormat:          "JWT",
		ExpireInHours:        1,
		RefreshExpireInHours: 1,
	}
	if _, err := ormer.Engine.Insert(application); err != nil {
		t.Fatalf("failed to insert test application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.ID(core.PK{application.Owner, application.Name}).Delete(&Application{})
	})

	user := &User{
		Owner:       orgName,
		Name:        userName,
		CreatedTime: util.GetCurrentTime(),
		Id:          util.GenerateId(),
		Type:        "normal-user",
		DisplayName: "Refresh Token Test User",
	}
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.ID(core.PK{user.Owner, user.Name}).Delete(&User{})
	})

	return application, user
}

// issueRefreshableToken mints an access/refresh token pair for user under
// application and persists it as a Token row, the same shape RefreshToken
// expects to find via GetTokenByRefreshToken. codeChallenge simulates
// whichever authorization request produced it: non-empty for a PKCE
// (public-client-style) grant, empty for a confidential-client grant that
// never presented a code_verifier.
func issueRefreshableToken(t *testing.T, application *Application, user *User, codeChallenge string) *Token {
	t.Helper()

	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, "", "", "", "openid", "", "")
	if err != nil {
		t.Fatalf("failed to generate jwt token: %v", err)
	}

	token := &Token{
		Owner:         application.Owner,
		Name:          tokenName,
		CreatedTime:   util.GetCurrentTime(),
		Application:   application.Name,
		Organization:  user.Owner,
		User:          user.Name,
		Code:          util.GenerateClientId(),
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		ExpiresIn:     int(application.ExpireInHours * 3600),
		Scope:         "openid",
		TokenType:     "Bearer",
		CodeChallenge: codeChallenge,
		CodeIsUsed:    true,
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("failed to persist test token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = DeleteToken(token)
	})

	return token
}

// TestRefreshTokenConfidentialClientRequiresSecret is the regression test for
// TC-2109FED0: the refresh_token grant must not mint new tokens for a
// confidential OAuth client unless the caller proves it holds that client's
// client_secret. Presenting only a valid, still-live refresh_token with the
// secret parameter omitted entirely must not be enough.
func TestRefreshTokenConfidentialClientRequiresSecret(t *testing.T) {
	createDatabase = false
	InitConfig()

	application, user := setupRefreshTokenFixtures(t)

	t.Run("MissingSecretIsRejected", func(t *testing.T) {
		// This application never used PKCE (codeChallenge == ""), i.e. it is
		// a confidential client, exactly like app-niro-alpha in the finding.
		tok := issueRefreshableToken(t, application, user, "")

		// clientSecret == "" simulates the client_secret form field being
		// omitted from the request entirely (controllers/token.go passes
		// through whatever ParseForm() produced, which is "" when absent).
		result, err := RefreshToken(application, "refresh_token", tok.RefreshToken, "", application.ClientId, "", "", "")
		if err != nil {
			t.Fatalf("RefreshToken returned unexpected error: %v", err)
		}

		tokenErr, ok := result.(*TokenError)
		if !ok {
			t.Fatalf("invariant violated: refresh_token grant issued new tokens for a confidential "+
				"client with client_secret omitted; got %T: %+v, want *TokenError{Error: %q}",
				result, result, InvalidClient)
		}
		if tokenErr.Error != InvalidClient {
			t.Fatalf("expected error %q, got %q (%s)", InvalidClient, tokenErr.Error, tokenErr.ErrorDescription)
		}
	})

	t.Run("CorrectSecretStillSucceeds", func(t *testing.T) {
		// Positive control: the legitimate flow (secret presented and
		// correct) must keep working - the fix must not lock out real
		// clients.
		tok := issueRefreshableToken(t, application, user, "")

		result, err := RefreshToken(application, "refresh_token", tok.RefreshToken, "", application.ClientId, application.ClientSecret, "", "")
		if err != nil {
			t.Fatalf("RefreshToken returned unexpected error: %v", err)
		}

		wrapper, ok := result.(*TokenWrapper)
		if !ok || wrapper.AccessToken == "" {
			t.Fatalf("legitimate refresh with the correct client_secret was rejected: %T: %+v", result, result)
		}
	})

	t.Run("WrongSecretIsRejected", func(t *testing.T) {
		// Negative control: an incorrect secret must still be rejected, so
		// the fix isn't merely disabling refresh entirely.
		tok := issueRefreshableToken(t, application, user, "")

		result, err := RefreshToken(application, "refresh_token", tok.RefreshToken, "", application.ClientId, "not-the-real-secret", "", "")
		if err != nil {
			t.Fatalf("RefreshToken returned unexpected error: %v", err)
		}

		tokenErr, ok := result.(*TokenError)
		if !ok {
			t.Fatalf("expected refresh with a wrong client_secret to be rejected, got %T: %+v", result, result)
		}
		if tokenErr.Error != InvalidClient {
			t.Fatalf("expected error %q, got %q (%s)", InvalidClient, tokenErr.Error, tokenErr.ErrorDescription)
		}
	})
}

// TestRefreshTokenPublicPKCEClientKeepsWorkingWithoutSecret guards the
// legitimate behavior the fix must preserve: a token that was originally
// obtained via PKCE (no client_secret involved at all) must still be
// refreshable without a client_secret, including across more than one
// refresh in a row.
func TestRefreshTokenPublicPKCEClientKeepsWorkingWithoutSecret(t *testing.T) {
	createDatabase = false
	InitConfig()

	application, user := setupRefreshTokenFixtures(t)

	// Non-empty CodeChallenge marks this token as having come from a PKCE
	// authorization_code exchange, i.e. a public client.
	tok := issueRefreshableToken(t, application, user, "pkce-challenge-marker")

	result, err := RefreshToken(application, "refresh_token", tok.RefreshToken, "", application.ClientId, "", "", "")
	if err != nil {
		t.Fatalf("RefreshToken returned unexpected error: %v", err)
	}
	wrapper, ok := result.(*TokenWrapper)
	if !ok || wrapper.AccessToken == "" || wrapper.RefreshToken == "" {
		t.Fatalf("PKCE/public client refresh without a client_secret was rejected: %T: %+v", result, result)
	}

	// Refresh again using the rotated refresh_token to prove the PKCE/public
	// nature of the token is preserved across refreshes, not just the first
	// one.
	result2, err := RefreshToken(application, "refresh_token", wrapper.RefreshToken, "", application.ClientId, "", "", "")
	if err != nil {
		t.Fatalf("RefreshToken returned unexpected error on second refresh: %v", err)
	}
	wrapper2, ok := result2.(*TokenWrapper)
	if !ok || wrapper2.AccessToken == "" {
		t.Fatalf("second consecutive PKCE/public client refresh without a client_secret was rejected: %T: %+v", result2, result2)
	}
}
