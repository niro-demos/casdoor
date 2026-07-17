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
	"fmt"
	"testing"
	"time"

	"github.com/casdoor/casdoor/util"
)

// setupRefreshTokenFixtures creates a throwaway org-scoped user and two
// OAuth applications ("legit" and "evil", modelling two unrelated clients in
// the same tenant, as in TC-16D98A7F) against a real database, exercising
// RefreshToken() the same way the HTTP API does. Everything is uniquely
// named per run so the test is self-contained and safe to re-run.
func setupRefreshTokenFixtures(t *testing.T) (legit *Application, evil *Application, user *User) {
	t.Helper()
	InitConfig()

	runId := fmt.Sprintf("%d", time.Now().UnixNano())

	cert := &Cert{
		Owner:           "admin",
		Name:            "cert-refresh-test-" + runId,
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     "Niro refresh-token regression test cert",
		Scope:           "JWT",
		Type:            "x509",
		CryptoAlgorithm: "RS256",
		BitSize:         2048,
		ExpireInYears:   20,
	}
	if ok, err := AddCert(cert); err != nil || !ok {
		t.Fatalf("failed to create test cert: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = DeleteCert(cert)
	})

	orgName := "org-refresh-test-" + runId
	user = &User{
		Owner:       orgName,
		Name:        "alice-" + runId,
		CreatedTime: util.GetCurrentTime(),
		Id:          util.GenerateId(),
		Type:        "normal-user",
		Password:    "irrelevant-not-used-by-refresh-flow",
	}
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.Delete(user)
	})

	newApp := func(suffix string) *Application {
		app := &Application{
			Owner:                "admin",
			Name:                 "app-refresh-test-" + runId + "-" + suffix,
			CreatedTime:          util.GetCurrentTime(),
			Organization:         orgName,
			Cert:                 cert.Name,
			ClientId:             "client-" + runId + "-" + suffix,
			ClientSecret:         "secret-" + runId + "-" + suffix,
			GrantTypes:           []string{"password", "refresh_token"},
			ExpireInHours:        2,
			RefreshExpireInHours: 24,
		}
		if ok, err := AddApplication(app); err != nil || !ok {
			t.Fatalf("failed to create test application %q: ok=%v err=%v", app.Name, ok, err)
		}
		t.Cleanup(func() {
			_, _ = ormer.Engine.Delete(&Application{Owner: app.Owner, Name: app.Name})
		})
		return app
	}

	legit = newApp("legit")
	evil = newApp("evil")
	return legit, evil, user
}

// mintToken mints and persists an access/refresh token pair for user against
// application, exactly like GetOAuthCode/GetPasswordToken do for a real
// login -- this is the "old" token a refresh_token grant would later
// redeem.
func mintToken(t *testing.T, application *Application, user *User, scope string) *Token {
	t.Helper()

	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, "", "", "", scope, "", "localhost:8000")
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("failed to persist token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.Delete(&Token{Owner: token.Owner, Name: token.Name})
	})

	return token
}

// TestRefreshTokenDoesNotEscalateScopeBeyondOriginalConsent is the
// regression test for TC-0FE6A993: a refresh_token grant must never widen
// access beyond what the user originally consented to. alice logs in with
// scope=openid only; redeeming her refresh_token while asking for
// "openid email phone address profile" must be rejected, not silently
// granted.
func TestRefreshTokenDoesNotEscalateScopeBeyondOriginalConsent(t *testing.T) {
	legit, _, user := setupRefreshTokenFixtures(t)

	oldToken := mintToken(t, legit, user, "openid")

	// ATTACK: redeem the refresh token asking for scopes never consented to.
	result, err := RefreshToken(legit, "refresh_token", oldToken.RefreshToken, "openid email phone address profile", legit.ClientId, legit.ClientSecret, "localhost:8000", "")
	if err != nil {
		t.Fatalf("RefreshToken returned an unexpected transport error: %v", err)
	}

	if wrapper, ok := result.(*TokenWrapper); ok {
		t.Fatalf("INVARIANT VIOLATED: refresh_token grant escalated scope from %q to %q -- it must reject a scope broader than originally granted, not silently mint a token with it (raw scope on new token: %q)",
			"openid", "openid email phone address profile", wrapper.Scope)
	}

	tokenError, ok := result.(*TokenError)
	if !ok {
		t.Fatalf("unexpected result type from RefreshToken: %T (%+v)", result, result)
	}
	if tokenError.Error != InvalidScope {
		t.Fatalf("expected error %q for an over-broad refresh scope, got %q (%s)", InvalidScope, tokenError.Error, tokenError.ErrorDescription)
	}

	// POSITIVE CONTROL: redeeming the same refresh token for its original,
	// already-granted scope must still succeed -- proves the rejection above
	// is the invariant, not a broken token/cert/user setup.
	result, err = RefreshToken(legit, "refresh_token", oldToken.RefreshToken, "openid", legit.ClientId, legit.ClientSecret, "localhost:8000", "")
	if err != nil {
		t.Fatalf("positive control: unexpected transport error: %v", err)
	}
	wrapper, ok := result.(*TokenWrapper)
	if !ok {
		t.Fatalf("positive control failed: legitimate same-scope refresh was rejected: %+v", result)
	}
	if wrapper.Scope != "openid" {
		t.Fatalf("positive control: expected scope %q on legitimately refreshed token, got %q", "openid", wrapper.Scope)
	}
}

// TestRefreshTokenRejectsWrongClient is the regression test for
// TC-16D98A7F: a refresh_token grant must only be redeemable by the same
// client application it was issued to, and that client must authenticate.
func TestRefreshTokenRejectsWrongClient(t *testing.T) {
	legit, evilApp, user := setupRefreshTokenFixtures(t)

	assertRejected := func(t *testing.T, label string, result interface{}, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: unexpected transport error: %v", label, err)
		}
		if wrapper, ok := result.(*TokenWrapper); ok {
			t.Fatalf("INVARIANT VIOLATED (%s): refresh_token grant minted a usable token (scope=%q) instead of rejecting the request", label, wrapper.Scope)
		}
		tokenError, ok := result.(*TokenError)
		if !ok {
			t.Fatalf("%s: unexpected result type from RefreshToken: %T (%+v)", label, result, result)
		}
		if tokenError.Error != InvalidGrant && tokenError.Error != InvalidClient {
			t.Fatalf("%s: expected invalid_grant/invalid_client, got %q (%s)", label, tokenError.Error, tokenError.ErrorDescription)
		}
	}

	t.Run("cross-client refresh with no client_secret is rejected", func(t *testing.T) {
		oldToken := mintToken(t, legit, user, "openid")
		// ATTACK: redeem alice's app-legit refresh_token against the evil
		// app's client_id, with no client_secret at all.
		result, err := RefreshToken(evilApp, "refresh_token", oldToken.RefreshToken, "", evilApp.ClientId, "", "localhost:8000", "")
		assertRejected(t, "cross-client, no secret", result, err)
	})

	t.Run("same-client refresh with no client_secret is rejected", func(t *testing.T) {
		oldToken := mintToken(t, legit, user, "openid")
		// ATTACK: redeem the refresh token against its own, correct
		// client_id, but never present a client_secret -- this isolates the
		// "client authentication is required" half of the invariant from
		// the "bound to the original client" half.
		result, err := RefreshToken(legit, "refresh_token", oldToken.RefreshToken, "", legit.ClientId, "", "localhost:8000", "")
		assertRejected(t, "same-client, no secret", result, err)
	})

	t.Run("legitimate same-client refresh with the correct secret succeeds", func(t *testing.T) {
		// POSITIVE CONTROL: a fresh token, refreshed by the same client with
		// its correct secret, must still succeed -- proves the rejections
		// above are the invariant, not a broken environment.
		oldToken := mintToken(t, legit, user, "openid")
		result, err := RefreshToken(legit, "refresh_token", oldToken.RefreshToken, "", legit.ClientId, legit.ClientSecret, "localhost:8000", "")
		if err != nil {
			t.Fatalf("positive control: unexpected transport error: %v", err)
		}
		wrapper, ok := result.(*TokenWrapper)
		if !ok {
			t.Fatalf("positive control failed: legitimate same-client refresh was rejected: %+v", result)
		}
		if wrapper.AccessToken == "" {
			t.Fatalf("positive control: expected a usable access_token, got none")
		}
	})
}
