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
	"strings"
	"testing"

	"github.com/xorm-io/xorm"
)

// Security invariant (TC-A6D39494):
//
//	A refresh token issued to one OAuth application/tenant must not be redeemable
//	by a *different* tenant's OAuth client to mint a fresh access token, even when
//	that client supplies its own valid client_id/client_secret.
//
// RefreshToken() loads the token record purely by refresh-token value
// (GetTokenByRefreshToken) and previously proceeded straight to user lookup /
// token minting without checking that the token was actually issued to the
// calling application/tenant. The authorization-code path already enforces this
// binding (token_oauth.go: `application.Name != token.Application`); this test
// pins the equivalent guard onto the refresh path.
//
// The test is hermetic: it stands up an in-memory SQLite ormer with only the
// Token (and Cert) tables and seeds a single cross-tenant token. It exercises
// the binding gate, which runs BEFORE any cert/user lookup or token minting, so
// no live target, seeded DB, or JWT signing material is required.

// bindingRejection is the invariant error the cross-tenant redemption must hit.
const bindingErrorMarker = "different application/tenant"

func withInMemoryOrmer(t *testing.T, tables ...interface{}) func() {
	t.Helper()

	engine, err := xorm.NewEngine("sqlite", "file:refresh_binding_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite engine: %v", err)
	}
	if err = engine.Sync2(tables...); err != nil {
		engine.Close()
		t.Fatalf("failed to sync tables: %v", err)
	}

	prev := ormer
	ormer = &Ormer{driverName: "sqlite", Engine: engine}
	return func() {
		ormer = prev
		engine.Close()
	}
}

// seedRefreshToken inserts a token record as if it had been issued to
// (application, organization) for user, and returns the refresh-token value.
func seedRefreshToken(t *testing.T, application, organization, user, refreshTokenValue string) {
	t.Helper()
	tok := &Token{
		Owner:            "admin",
		Name:             "token-" + refreshTokenValue,
		Application:      application,
		Organization:     organization,
		User:             user,
		RefreshToken:     refreshTokenValue,
		RefreshTokenHash: getTokenHash(refreshTokenValue),
		ExpiresIn:        604800,
		Scope:            "read",
		TokenType:        "Bearer",
	}
	if _, err := ormer.Engine.Insert(tok); err != nil {
		t.Fatalf("failed to seed token: %v", err)
	}
}

// TestRefreshTokenRejectsCrossTenantRedemption is the security regression test.
//
// A refresh token issued to the "globex" tenant's app must be rejected with
// invalid_grant when redeemed through the "acme" tenant's OAuth client, before
// any user lookup or token minting. The same-tenant control proves the setup is
// healthy: it is NOT rejected by the binding gate (it proceeds past it and fails
// later for an unrelated reason — missing signing cert in this hermetic setup),
// so the cross-tenant failure is provably the tenant-binding invariant and not a
// broken environment.
func TestRefreshTokenRejectsCrossTenantRedemption(t *testing.T) {
	cleanup := withInMemoryOrmer(t, new(Token), new(Cert))
	defer cleanup()

	const secret = "acme-client-secret"

	acmeApp := &Application{
		Owner:        "admin",
		Name:         "app-acme",
		Organization: "acme",
		ClientId:     "acme-client-id",
		ClientSecret: secret,
	}
	globexApp := &Application{
		Owner:        "admin",
		Name:         "app-globex",
		Organization: "globex",
		ClientId:     "globex-client-id",
		ClientSecret: secret,
	}

	// ---- Attack: a globex-issued refresh token redeemed via acme's client. ----
	seedRefreshToken(t, "app-globex", "globex", "carol", "globex-issued-rt-attack")
	res, err := RefreshToken(acmeApp, "refresh_token", "globex-issued-rt-attack", "", acmeApp.ClientId, secret, "http://localhost", "")
	if err != nil {
		t.Fatalf("attack: unexpected internal error: %v", err)
	}

	if _, ok := res.(*TokenWrapper); ok {
		t.Fatalf("INVARIANT VIOLATED: acme's client redeemed a globex-issued refresh token and minted a token set; expected invalid_grant rejection")
	}
	te, ok := res.(*TokenError)
	if !ok {
		t.Fatalf("attack: expected *TokenError, got %T (%v)", res, res)
	}
	if te.Error != InvalidGrant {
		t.Fatalf("attack: expected error %q, got %q (desc=%q)", InvalidGrant, te.Error, te.ErrorDescription)
	}
	if !strings.Contains(te.ErrorDescription, bindingErrorMarker) {
		t.Fatalf("attack: rejection was not the tenant-binding guard; got desc=%q", te.ErrorDescription)
	}

	// ---- Control: a globex-issued refresh token redeemed via globex's own ----
	// client must NOT be stopped by the binding gate. In this hermetic setup it
	// proceeds past the binding check and fails later (no signing cert), which is
	// a DIFFERENT error than the binding rejection — proving the gate is specific
	// to the cross-tenant case.
	seedRefreshToken(t, "app-globex", "globex", "carol", "globex-issued-rt-control")
	ctrl, err := RefreshToken(globexApp, "refresh_token", "globex-issued-rt-control", "", globexApp.ClientId, secret, "http://localhost", "")
	if err != nil {
		// A downstream internal error is acceptable for the control; the point is
		// only that the request got past the tenant-binding gate.
		return
	}
	if cte, ok := ctrl.(*TokenError); ok {
		if cte.Error == InvalidGrant && strings.Contains(cte.ErrorDescription, bindingErrorMarker) {
			t.Fatalf("control: same-tenant redemption was wrongly rejected by the tenant-binding guard (desc=%q); the guard must fire only cross-tenant", cte.ErrorDescription)
		}
	}
}
