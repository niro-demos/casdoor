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

package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var providerTestEnvOnce sync.Once

func setupProviderTestEnv(t *testing.T) {
	t.Helper()
	providerTestEnvOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
	})
}

// newProviderTestController builds a real *ApiController wired to an
// in-memory request/response pair, the same way beego's router does for a
// live GET /api/get-provider?id=... request. currentUserId mirrors what
// routers/authz_filter.go's ApiFilter stashes on the context after
// authenticating the caller: it is set on *every* request, including an
// empty string for an anonymous/unauthenticated caller (see ApiFilter's
// `ctx.Input.SetData("currentUserId", username)`). Setting it unconditionally
// here - rather than only for authenticated callers - matters: it is what
// lets GetSessionUsername() short-circuit before touching the beego session
// store, which this bare test context does not have configured.
func newProviderTestController(id string, currentUserId string) (*ApiController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/api/get-provider?id="+id, nil)
	w := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(w, req)
	ctx.Input.SetData("currentUserId", currentUserId)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetProvider", c)
	return c, w
}

func decodeProviderResponse(t *testing.T, w *httptest.ResponseRecorder) Response {
	t.Helper()
	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), err)
	}
	return resp
}

// TestGetProviderDeniesAnonymousReadOfSensitiveCategory is the regression
// test for TC-1B0D9020: an unauthenticated, non-member caller must not be
// able to read another organization's OAuth/SAML/Storage/... connector
// config (client IDs, hosts, ports, endpoints) just by guessing its
// "owner/name" id - the exact exploit in the PoC (an anonymous GET against
// an "acme"-owned OAuth provider).
func TestGetProviderDeniesAnonymousReadOfSensitiveCategory(t *testing.T) {
	setupProviderTestEnv(t)

	org := "provider-test-org-" + util.GenerateId()
	provider := &object.Provider{
		Owner:        org,
		Name:         "provider-test-oauth-" + util.GenerateId(),
		Category:     "OAuth",
		Type:         "Google",
		ClientId:     "provider-test-client-id",
		ClientSecret: "provider-test-client-secret",
		Host:         "internal-idp.example.com",
		Port:         443,
	}
	ok, err := object.AddProvider(provider)
	if err != nil || !ok {
		t.Fatalf("AddProvider() = (%v, %v), want (true, nil)", ok, err)
	}
	defer func() { _, _ = object.DeleteProvider(provider) }()

	id := util.GetId(provider.Owner, provider.Name)

	// The invariant: an anonymous caller must be denied.
	c, w := newProviderTestController(id, "")
	c.GetProvider()
	resp := decodeProviderResponse(t, w)
	if resp.Status != "error" {
		t.Fatalf("anonymous GetProvider(OAuth provider) = %+v, want status=error", resp)
	}

	// Positive control: a global admin (built-in/admin, created by
	// object.InitDb()) must still be able to read the very same provider -
	// proves the deny above is the ownership/category invariant, not the
	// provider being unreadable outright or a broken environment.
	c, w = newProviderTestController(id, "built-in/admin")
	c.GetProvider()
	resp = decodeProviderResponse(t, w)
	if resp.Status != "ok" {
		t.Fatalf("global-admin GetProvider(OAuth provider) = %+v, want status=ok (control)", resp)
	}
}

// TestGetProviderAllowsAnonymousReadOfPubliclyReadableCategory guards
// against over-correcting TC-1B0D9020: a couple of pre-login UI flows
// (web/src/auth/TelegramLogin.js, web/src/QrCodePage.js) legitimately read a
// specific Notification/Payment provider before the caller has a session,
// and must keep working.
func TestGetProviderAllowsAnonymousReadOfPubliclyReadableCategory(t *testing.T) {
	setupProviderTestEnv(t)

	org := "provider-test-org-" + util.GenerateId()
	provider := &object.Provider{
		Owner:    org,
		Name:     "provider-test-telegram-" + util.GenerateId(),
		Category: "Notification",
		Type:     "Telegram",
		ClientId: "provider-test-bot-username",
	}
	ok, err := object.AddProvider(provider)
	if err != nil || !ok {
		t.Fatalf("AddProvider() = (%v, %v), want (true, nil)", ok, err)
	}
	defer func() { _, _ = object.DeleteProvider(provider) }()

	id := util.GetId(provider.Owner, provider.Name)

	c, w := newProviderTestController(id, "")
	c.GetProvider()
	resp := decodeProviderResponse(t, w)
	if resp.Status != "ok" {
		t.Fatalf("anonymous GetProvider(Notification provider) = %+v, want status=ok", resp)
	}
}
