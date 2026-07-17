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
	"time"

	"github.com/casdoor/casdoor/util"
)

// TestGetAuthorizationCodeTokenRejectsRedirectUriMismatch is the regression
// test for TC-2DE6D591: the authorization_code token exchange
// (POST /api/login/oauth/access_token) must bind the redeemed code to the
// redirect_uri that was used to obtain it (RFC 6749 4.1.3). A code issued
// for one redirect_uri must not be redeemable with a different,
// attacker-controlled redirect_uri.
func TestGetAuthorizationCodeTokenRejectsRedirectUriMismatch(t *testing.T) {
	InitConfig()

	const legitRedirectUri = "https://legit.example.com/callback"
	const attackerRedirectUri = "https://attacker.example.com/callback"

	application := &Application{
		Owner:        "admin",
		Name:         "test-app-tc-2de6d591",
		ClientId:     "test-client-tc-2de6d591",
		ClientSecret: "test-client-secret-tc-2de6d591",
	}

	// issueCode inserts a Token row representing a freshly-issued, unused
	// authorization code bound to redirectUri, mirroring what GetOAuthCode
	// persists at /login/oauth/authorize time.
	issueCode := func(t *testing.T, redirectUri string) string {
		t.Helper()
		code := util.GenerateClientId()
		token := &Token{
			Owner:        application.Owner,
			Name:         util.GenerateId(),
			CreatedTime:  util.GetCurrentTime(),
			Application:  application.Name,
			Organization: "test-org-tc-2de6d591",
			User:         "test-user-tc-2de6d591",
			Code:         code,
			RedirectUri:  redirectUri,
			CodeIsUsed:   false,
			CodeExpireIn: time.Now().Add(5 * time.Minute).Unix(),
		}
		affected, err := AddToken(token)
		if err != nil {
			t.Fatalf("AddToken() error = %v", err)
		}
		if !affected {
			t.Fatalf("AddToken() did not insert a row")
		}
		t.Cleanup(func() {
			_, _ = DeleteToken(token)
		})
		return code
	}

	// --- Attack: redeem a code issued for legitRedirectUri using a
	// different, attacker-controlled redirect_uri that was never used to
	// obtain it. Per RFC 6749 4.1.3 this MUST be rejected with invalid_grant. ---
	t.Run("mismatched redirect_uri is rejected", func(t *testing.T) {
		attackCode := issueCode(t, legitRedirectUri)

		gotToken, tokenErr, err := GetAuthorizationCodeToken(application, application.ClientSecret, attackCode, "", "", attackerRedirectUri)
		if err != nil {
			t.Fatalf("GetAuthorizationCodeToken() unexpected error = %v", err)
		}
		if tokenErr == nil {
			t.Fatalf("GetAuthorizationCodeToken() with mismatched redirect_uri = (token=%+v, nil error) — want invalid_grant TokenError", gotToken)
		}
		if tokenErr.Error != InvalidGrant {
			t.Fatalf("GetAuthorizationCodeToken() error = %q, want %q", tokenErr.Error, InvalidGrant)
		}
		if gotToken != nil {
			t.Fatalf("GetAuthorizationCodeToken() issued a token despite the redirect_uri mismatch: %+v", gotToken)
		}
	})

	// --- Control: a fresh code redeemed with the SAME redirect_uri it was
	// issued for must still succeed — proves the check is specific to the
	// mismatch and not a broken environment. ---
	t.Run("matching redirect_uri still succeeds", func(t *testing.T) {
		controlCode := issueCode(t, legitRedirectUri)

		gotToken, tokenErr, err := GetAuthorizationCodeToken(application, application.ClientSecret, controlCode, "", "", legitRedirectUri)
		if err != nil {
			t.Fatalf("GetAuthorizationCodeToken() unexpected error = %v", err)
		}
		if tokenErr != nil {
			t.Fatalf("GetAuthorizationCodeToken() rejected a legitimate exchange with matching redirect_uri: %+v", tokenErr)
		}
		if gotToken == nil {
			t.Fatalf("GetAuthorizationCodeToken() returned nil token for a legitimate exchange")
		}
	})
}
