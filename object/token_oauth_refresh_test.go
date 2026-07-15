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
)

// TestRefreshTokenRejectsMismatchedApplication is the regression test for
// TC-40243EFD. It asserts the invariant from finding.json:
//
//	"A refresh token issued to one OAuth application must not be redeemable
//	for a new access token using a different application's client
//	credentials."
//
// It models TC-40243EFD's PoC (two OAuth applications in the same
// organization, a refresh token minted for one of them) directly against
// RefreshToken() in object/token_oauth_util.go, mirroring the equivalent
// application-binding check that GetAuthorizationCodeToken() already
// performs in object/token_oauth.go (`application.Name != token.Application`).
func TestRefreshTokenRejectsMismatchedApplication(t *testing.T) {
	InitConfig()

	suffix := util.GenerateId()
	orgName := "niro-poc-org-" + suffix
	userName := "niro-poc-user-" + suffix

	// --- Setup: an isolated organization with two independent OAuth
	// applications ("owner" and "other"), and one user in that organization.
	// Both applications rely on the default cert (admin/cert-built-in), so
	// only the application-binding check under test differs between them.
	organization := &Organization{
		Owner:       "admin",
		Name:        orgName,
		DisplayName: "Niro PoC org for TC-40243EFD",
	}
	if ok, err := AddOrganization(organization); err != nil || !ok {
		t.Fatalf("failed to create test organization: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = DeleteOrganization(organization) }()

	appOwner := &Application{
		Owner:                "admin",
		Name:                 "niro-poc-app-owner-" + suffix,
		Organization:         orgName,
		DisplayName:          "Niro PoC owning application",
		EnablePassword:       true,
		ExpireInHours:        1,
		RefreshExpireInHours: 24,
	}
	if ok, err := AddApplication(appOwner); err != nil || !ok {
		t.Fatalf("failed to create owning application: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = DeleteApplication(appOwner) }()

	appOther := &Application{
		Owner:                "admin",
		Name:                 "niro-poc-app-other-" + suffix,
		Organization:         orgName,
		DisplayName:          "Niro PoC unrelated application",
		EnablePassword:       true,
		ExpireInHours:        1,
		RefreshExpireInHours: 24,
	}
	if ok, err := AddApplication(appOther); err != nil || !ok {
		t.Fatalf("failed to create unrelated application: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = DeleteApplication(appOther) }()

	user := &User{
		Owner:    orgName,
		Name:     userName,
		Password: "Niro-Poc-Pw-1!",
		Type:     "normal-user",
	}
	if ok, err := AddUser(user, "en"); err != nil || !ok {
		t.Fatalf("failed to create test user: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = deleteUser(user) }()

	// --- Mint a refresh token bound to appOwner (equivalent to the PoC's
	// password-grant login against app-acme's client_id/client_secret). ---
	accessToken, refreshToken, tokenName, err := generateJwtToken(appOwner, user, "", "", "", "openid profile", "", "")
	if err != nil {
		t.Fatalf("failed to generate token for appOwner: %v", err)
	}

	token := &Token{
		Owner:        appOwner.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  appOwner.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(appOwner.ExpireInHours * float64(hourSeconds)),
		Scope:        "openid profile",
		TokenType:    "Bearer",
	}
	if ok, err := AddToken(token); err != nil || !ok {
		t.Fatalf("failed to persist token record: ok=%v err=%v", ok, err)
	}
	defer func() { _, _ = DeleteToken(token) }()

	// --- Attack: redeem appOwner's refresh token using appOther's own
	// (valid) client_id/client_secret, exactly like TC-40243EFD's step 2. ---
	result, err := RefreshToken(appOther, "refresh_token", refreshToken, "", appOther.ClientId, appOther.ClientSecret, "", "")
	if err != nil {
		t.Fatalf("RefreshToken returned an unexpected transport error: %v", err)
	}

	tokenErr, isTokenErr := result.(*TokenError)
	if !isTokenErr || tokenErr.Error != InvalidGrant {
		t.Fatalf("invariant violated: a refresh token issued to application %q must not be redeemable by unrelated application %q; RefreshToken() returned %#v, want *TokenError{Error: %q}",
			appOwner.Name, appOther.Name, result, InvalidGrant)
	}

	// --- Control: appOwner redeeming its own refresh token must still
	// succeed. This proves the failure above is the missing application
	// binding check, not a broken test environment. ---
	ctrlResult, err := RefreshToken(appOwner, "refresh_token", refreshToken, "", appOwner.ClientId, appOwner.ClientSecret, "", "")
	if err != nil {
		t.Fatalf("control RefreshToken (legitimate owner) returned an unexpected error: %v", err)
	}
	ctrlWrapper, isWrapper := ctrlResult.(*TokenWrapper)
	if !isWrapper || ctrlWrapper.AccessToken == "" {
		t.Fatalf("control failed: the owning application redeeming its own refresh token should succeed, got %#v", ctrlResult)
	}

	// The successful control redemption above replaced `token` with a new
	// token record (RefreshToken() deletes the old one and issues a new
	// one) — clean that new record up too.
	if newToken, err := GetTokenByRefreshToken(ctrlWrapper.RefreshToken); err == nil && newToken != nil {
		_, _ = DeleteToken(newToken)
	}
}
