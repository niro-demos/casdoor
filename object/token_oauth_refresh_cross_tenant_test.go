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
	"testing"

	"github.com/casdoor/casdoor/util"
)

// TestRefreshTokenRejectsCrossApplicationRedemption is a regression test for
// TC-343E4454: a refresh token issued to one OAuth application/tenant must
// not be redeemable through a different, unrelated OAuth application's
// client credentials to mint a fresh access token for a different tenant's
// user account of the same username.
//
// It reproduces the finding's PoC (niro/findings/TC-343E4454/poc.go) using
// the project's own object-layer functions rather than the seeded live
// fixtures: two organizations, each with its own application and its own
// "admin" user, mirroring niro-alpha/niro-beta.
func TestRefreshTokenRejectsCrossApplicationRedemption(t *testing.T) {
	InitConfig()

	suffix := util.GenerateId()[:8]
	orgAName := "xtenant-a-" + suffix
	orgBName := "xtenant-b-" + suffix
	appAName := "xtenant-app-a-" + suffix
	appBName := "xtenant-app-b-" + suffix
	const (
		username = "admin"
		password = "TestRefreshXTenant123!"
	)

	orgA := &Organization{Owner: "admin", Name: orgAName, PasswordType: "plain"}
	orgB := &Organization{Owner: "admin", Name: orgBName, PasswordType: "plain"}
	if _, err := AddOrganization(orgA); err != nil {
		t.Fatalf("failed to create organization A: %v", err)
	}
	t.Cleanup(func() { _, _ = DeleteOrganization(orgA) })
	if _, err := AddOrganization(orgB); err != nil {
		t.Fatalf("failed to create organization B: %v", err)
	}
	t.Cleanup(func() { _, _ = DeleteOrganization(orgB) })

	// Both applications deliberately leave Cert empty so they both fall back
	// to the shared default cert -- exactly the environment the finding was
	// reproduced in, so a signature-validation quirk cannot be mistaken for
	// the fix under test.
	appA := &Application{
		Owner:          "admin",
		Name:           appAName,
		Organization:   orgAName,
		ClientId:       util.GenerateClientId(),
		ClientSecret:   util.GenerateClientId(),
		EnablePassword: true,
		ExpireInHours:  1,
	}
	appB := &Application{
		Owner:          "admin",
		Name:           appBName,
		Organization:   orgBName,
		ClientId:       util.GenerateClientId(),
		ClientSecret:   util.GenerateClientId(),
		EnablePassword: true,
		ExpireInHours:  1,
	}
	if ok, err := AddApplication(appA); err != nil || !ok {
		t.Fatalf("failed to create application A: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = DeleteApplication(appA) })
	if ok, err := AddApplication(appB); err != nil || !ok {
		t.Fatalf("failed to create application B: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = DeleteApplication(appB) })

	userA := &User{Owner: orgAName, Name: username, Id: util.GenerateId(), Password: password}
	userB := &User{Owner: orgBName, Name: username, Id: util.GenerateId(), Password: password}
	if ok, err := AddUser(userA, "en"); err != nil || !ok {
		t.Fatalf("failed to create user A: ok=%v err=%v", ok, err)
	}
	// Use the unexported raw delete (not DeleteUser) in cleanup: DeleteUser
	// also deregisters the user from the package-level Casbin group
	// enforcer, which is wired up by InitUserManager() in main.go and isn't
	// initialized by object.InitConfig() alone -- unrelated to the fix under
	// test, so avoid depending on it here.
	t.Cleanup(func() { _, _ = deleteUser(userA) })
	if ok, err := AddUser(userB, "en"); err != nil || !ok {
		t.Fatalf("failed to create user B: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = deleteUser(userB) })

	// login obtains a FRESH refresh token for tenant-A's admin via a
	// legitimate password grant against A's own application. Refresh tokens
	// are single-use/rotated (RefreshToken deletes the old Token row after
	// minting a new one), so each leg below needs its own independently
	// obtained refresh token.
	login := func() *Token {
		token, tokenErr, err := GetPasswordToken(appA, username, password, "openid", "")
		if err != nil {
			t.Fatalf("login error: %v", err)
		}
		if tokenErr != nil {
			t.Fatalf("login unexpectedly failed: %s %s", tokenErr.Error, tokenErr.ErrorDescription)
		}
		if token == nil || token.RefreshToken == "" {
			t.Fatalf("login did not return a refresh token")
		}
		return token
	}

	// Positive control: redeeming a fresh tenant-A refresh token through
	// tenant-A's OWN application must keep working and must stay in tenant
	// A. This proves the refresh flow itself is healthy, so a failure below
	// is the target invariant, not a broken test setup.
	ctrlToken := login()
	ctrlResult, err := RefreshToken(nil, "refresh_token", ctrlToken.RefreshToken, "openid", appA.ClientId, appA.ClientSecret, "", "")
	if err != nil {
		t.Fatalf("control refresh error: %v", err)
	}
	ctrlWrapper, ok := ctrlResult.(*TokenWrapper)
	if !ok {
		t.Fatalf("control (same-application refresh) unexpectedly failed: %#v", ctrlResult)
	}
	ctrlNewToken, err := GetTokenByAccessToken(ctrlWrapper.AccessToken)
	if err != nil || ctrlNewToken == nil {
		t.Fatalf("could not look up control token row: %v", err)
	}
	if ctrlNewToken.Organization != orgAName || ctrlNewToken.Application != appAName {
		t.Fatalf("control refresh minted a token outside tenant A: organization=%s application=%s", ctrlNewToken.Organization, ctrlNewToken.Application)
	}

	// The exploit: redeem a SECOND, independent, still-unused tenant-A
	// refresh token, but present tenant-B's application client_id +
	// client_secret -- an application niro-alpha/admin (here, orgA's admin)
	// never authorized, belonging to a completely different tenant.
	exploitToken := login()
	exploitResult, err := RefreshToken(nil, "refresh_token", exploitToken.RefreshToken, "openid", appB.ClientId, appB.ClientSecret, "", "")
	if err != nil {
		t.Fatalf("exploit refresh error: %v", err)
	}

	// Secure behavior: the server must reject this cross-application
	// redemption with invalid_grant, never mint a token.
	tokenErr, ok := exploitResult.(*TokenError)
	if !ok {
		wrapper, isWrapper := exploitResult.(*TokenWrapper)
		if isWrapper {
			mintedToken, lookupErr := GetTokenByAccessToken(wrapper.AccessToken)
			if lookupErr == nil && mintedToken != nil {
				t.Fatalf("INVARIANT VIOLATED: a refresh token issued to tenant %s (application %s) was redeemed through application %s and minted a live access token for tenant=%s user=%s (application-B's own tenant), instead of being rejected",
					orgAName, appAName, appBName, mintedToken.Organization, mintedToken.User)
			}
		}
		t.Fatalf("expected cross-application refresh redemption to be rejected with an invalid_grant TokenError, got: %#v", exploitResult)
	}
	if tokenErr.Error != InvalidGrant {
		t.Fatalf("expected error=%s for cross-application refresh redemption, got error=%s (%s)", InvalidGrant, tokenErr.Error, tokenErr.ErrorDescription)
	}
}
