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
	"github.com/xorm-io/xorm"
)

func TestRefreshTokenRejectsTokenIssuedToDifferentClient(t *testing.T) {
	appA, appB, refreshToken := setupOAuthClientBindingTest(t)

	result, err := RefreshToken(appB, "refresh_token", refreshToken, "", appB.ClientId, appB.ClientSecret, "example.com", "")
	if err != nil {
		t.Fatalf("RefreshToken() returned error: %v", err)
	}

	tokenError, ok := result.(*TokenError)
	if !ok {
		t.Fatalf("RefreshToken() = %T, want *TokenError for refresh token issued to %s", result, appA.GetId())
	}
	if tokenError.Error != InvalidGrant {
		t.Fatalf("RefreshToken() error = %q, want %q", tokenError.Error, InvalidGrant)
	}
	if tokenError.ErrorDescription != "refresh token was not issued to this client" {
		t.Fatalf("RefreshToken() description = %q", tokenError.ErrorDescription)
	}
}

func TestRefreshTokenAllowsTokenIssuedToSameClient(t *testing.T) {
	appA, _, refreshToken := setupOAuthClientBindingTest(t)

	result, err := RefreshToken(appA, "refresh_token", refreshToken, "", appA.ClientId, appA.ClientSecret, "example.com", "")
	if err != nil {
		t.Fatalf("RefreshToken() returned error: %v", err)
	}

	wrapper, ok := result.(*TokenWrapper)
	if !ok {
		t.Fatalf("RefreshToken() = %T, want *TokenWrapper", result)
	}
	if wrapper.AccessToken == "" || wrapper.RefreshToken == "" {
		t.Fatalf("RefreshToken() returned empty replacement tokens: %+v", wrapper)
	}
}

func TestTokenBelongsToApplication(t *testing.T) {
	appA := &Application{Owner: "admin", Name: "app-a"}
	appB := &Application{Owner: "admin", Name: "app-b"}
	token := &Token{Owner: appA.Owner, Application: appA.Name}

	if !TokenBelongsToApplication(token, appA) {
		t.Fatal("TokenBelongsToApplication() rejected the issuing application")
	}
	if TokenBelongsToApplication(token, appB) {
		t.Fatal("TokenBelongsToApplication() allowed a different application")
	}
	if TokenBelongsToApplication(nil, appA) {
		t.Fatal("TokenBelongsToApplication() allowed a nil token")
	}
	if TokenBelongsToApplication(token, nil) {
		t.Fatal("TokenBelongsToApplication() allowed a nil application")
	}
}

func setupOAuthClientBindingTest(t *testing.T) (*Application, *Application, string) {
	t.Helper()

	engine, err := xorm.NewEngine("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	t.Cleanup(func() {
		_ = engine.Close()
	})

	previousOrmer := ormer
	ormer = &Ormer{Engine: engine}
	t.Cleanup(func() {
		ormer = previousOrmer
	})

	if err := engine.Sync2(new(Cert), new(Application), new(Token), new(User), new(Role), new(Permission), new(Group), new(ThirdPartyLink)); err != nil {
		t.Fatalf("Sync2() error: %v", err)
	}

	certificate, privateKey, err := generateRsaKeys(2048, 512, 1, "OAuth Client Binding Test", "Casdoor")
	if err != nil {
		t.Fatalf("generateRsaKeys() error: %v", err)
	}

	cert := &Cert{
		Owner:       "admin",
		Name:        "cert-client-binding",
		Certificate: certificate,
		PrivateKey:  privateKey,
	}
	if _, err := engine.Insert(cert); err != nil {
		t.Fatalf("insert cert error: %v", err)
	}

	user := &User{
		Owner: "org-client-binding",
		Name:  "alice",
		Id:    "alice-id",
	}
	if _, err := engine.Insert(user); err != nil {
		t.Fatalf("insert user error: %v", err)
	}

	appA := newClientBindingApplication("app-a", "client-a", "secret-a", cert.Name)
	appB := newClientBindingApplication("app-b", "client-b", "secret-b", cert.Name)
	if _, err := engine.Insert(appA, appB); err != nil {
		t.Fatalf("insert applications error: %v", err)
	}

	accessToken, refreshToken, tokenName, err := generateJwtToken(appA, user, "", "", "", "openid", "", "example.com")
	if err != nil {
		t.Fatalf("generateJwtToken() error: %v", err)
	}

	token := &Token{
		Owner:        appA.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  appA.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(appA.ExpireInHours * float64(hourSeconds)),
		Scope:        "openid",
		TokenType:    "Bearer",
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("AddToken() error: %v", err)
	}

	return appA, appB, refreshToken
}

func newClientBindingApplication(name string, clientId string, clientSecret string, cert string) *Application {
	return &Application{
		Owner:                "admin",
		Name:                 name,
		Organization:         "org-client-binding",
		Cert:                 cert,
		ClientId:             clientId,
		ClientSecret:         clientSecret,
		TokenFormat:          "JWT",
		TokenSigningMethod:   "RS256",
		ExpireInHours:        1,
		RefreshExpireInHours: 1,
	}
}
