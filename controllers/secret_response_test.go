package controllers

import (
	"encoding/json"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestTokenResponseOmitsReusableCredentials(t *testing.T) {
	token := &object.Token{
		Owner:            "admin",
		Name:             "token-id",
		CreatedTime:      "2026-07-28T00:00:00Z",
		Application:      "app-niro-alpha",
		Organization:     "niro-alpha",
		User:             "alice",
		Code:             "oauth-code",
		AccessToken:      "raw-access-token",
		RefreshToken:     "raw-refresh-token",
		AccessTokenHash:  "access-hash",
		RefreshTokenHash: "refresh-hash",
		ExpiresIn:        3600,
		Scope:            "openid profile",
		TokenType:        "Bearer",
		GrantType:        "authorization_code",
		CodeChallenge:    "code-challenge",
		CodeIsUsed:       false,
		CodeExpireIn:     123,
		Resource:         "resource",
		DPoPJkt:          "dpop-thumbprint",
	}

	raw, err := json.Marshal(toTokenResponse(token))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"accessToken", "refreshToken", "code", "accessTokenHash", "refreshTokenHash", "codeChallenge"} {
		if _, ok := fields[field]; ok {
			t.Fatalf("token response exposes reusable credential field %q: %s", field, raw)
		}
	}
	if fields["owner"] != token.Owner || fields["name"] != token.Name || fields["user"] != token.User {
		t.Fatalf("token metadata was not preserved: %s", raw)
	}
}

func TestSessionResponseOmitsBrowserSessionIDs(t *testing.T) {
	session := &object.Session{
		Owner:       "niro-alpha",
		Name:        "bob",
		Application: "app-niro-alpha",
		CreatedTime: "2026-07-28T00:00:00Z",
		SessionId:   []string{"reusable-browser-session"},
	}

	raw, err := json.Marshal(toSessionResponse(session))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}

	if _, ok := fields["sessionId"]; ok {
		t.Fatalf("session response exposes reusable browser session IDs: %s", raw)
	}
	if fields["owner"] != session.Owner || fields["name"] != session.Name || fields["application"] != session.Application {
		t.Fatalf("session metadata was not preserved: %s", raw)
	}
}

func TestCertResponseForTenantAdminOmitsGlobalPrivateKeys(t *testing.T) {
	certs := []*object.Cert{
		{Owner: "admin", Name: "cert-built-in", PrivateKey: "global-private-key"},
		{Owner: "niro-alpha", Name: "tenant-cert", PrivateKey: "tenant-private-key"},
	}

	got, err := toCertResponse(certs, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range got {
		if cert.Owner == "admin" {
			t.Fatalf("non-global cert response includes global cert %s/%s", cert.Owner, cert.Name)
		}
		if cert.PrivateKey != "***" {
			t.Fatalf("non-global cert response exposes private key for %s/%s", cert.Owner, cert.Name)
		}
	}

	global, err := toCertResponse(certs, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(global) != len(certs) || global[0].PrivateKey != "global-private-key" {
		t.Fatalf("global admin cert response should preserve full cert inventory: %#v", global)
	}
}
