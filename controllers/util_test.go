// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"net/http/httptest"
	"strings"
	"testing"

	beegoCtx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// newAnonymousApiController builds an ApiController wired to a fresh beego
// request/response context that carries no identity at all. This mirrors
// exactly what routers.ApiFilter leaves in the request context for a caller
// it could not identify by session cookie or clientId/clientSecret: it still
// calls ctx.Input.SetData("currentUserId", username) with an empty username
// for the "anonymous/anonymous" subject (routers/authz_filter.go:330-338)
// before the controller action ever runs.
func newAnonymousApiController(target string) *ApiController {
	req := httptest.NewRequest("POST", target, nil)
	w := httptest.NewRecorder()

	ctx := beegoCtx.NewContext()
	ctx.Reset(w, req)
	ctx.Input.SetData("currentUserId", "")

	c := &ApiController{}
	c.Ctx = ctx
	c.Data = make(map[interface{}]interface{})
	return c
}

// newSignedInApiController is the authenticated counterpart: it mirrors what
// ApiFilter leaves in the context for a caller it successfully identified,
// whether via session cookie or clientId/clientSecret (both are resolved by
// getUsername before ApiFilter ever calls ctx.Input.SetData, see
// routers/authz_filter.go:74-107). GetSessionUsername prefers this
// context-stored value over the beego session store (controllers/base.go:108-114),
// so setting it here is sufficient to represent "signed in" for either auth
// method without needing a real session store.
func newSignedInApiController(target, userId string) *ApiController {
	c := newAnonymousApiController(target)
	c.Ctx.Input.SetData("currentUserId", userId)
	return c
}

// TestGetProviderFromContextRequiresSignIn is the regression test for
// TC-59AF79DE: an unauthenticated caller must not be able to skip the login
// gate in GetProviderFromContext by supplying an explicit provider — via the
// `provider` query param, the `field=provider&value=...` alias, or a
// `Direct/<provider>/...` fullFilePath prefix — since every endpoint that
// calls this function (e.g. POST /api/upload-resource, /api/delete-resource)
// inherits whatever it decides about authentication.
func TestGetProviderFromContextRequiresSignIn(t *testing.T) {
	object.InitConfig()

	providerName := "niro-tc59af79de-provider"
	provider := &object.Provider{
		Owner:       "admin",
		Name:        providerName,
		DisplayName: "Niro regression test storage provider",
		Category:    "Storage",
		Type:        object.ProviderTypeLocalFileSystem,
	}
	ok, err := object.AddProvider(provider)
	if err != nil || !ok {
		t.Fatalf("test setup: could not create throwaway storage provider: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteProvider(provider)
	})

	base := "/api/upload-resource?owner=niro-alpha&user=victim&application=app-niro-alpha&tag=idCardFront"

	cases := []struct {
		name   string
		target string
	}{
		{"explicit provider query param", base + "&fullFilePath=/idcard/victim/idfront.png&provider=" + providerName},
		{"field=provider&value=... alias", base + "&fullFilePath=/idcard/victim/idfront.png&field=provider&value=" + providerName},
		{"Direct/<provider>/... fullFilePath prefix", base + "&fullFilePath=Direct/" + providerName + "/idcard/victim/idfront.png"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newAnonymousApiController(tc.target)

			gotProvider, err := c.GetProviderFromContext("Storage")

			// Invariant: an unauthenticated visitor must always be turned
			// away with a login-required error, regardless of which query
			// parameters are supplied.
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "login") {
				t.Fatalf("invariant violated: unauthenticated caller was not rejected with a login-required error (provider=%v, err=%v)", gotProvider, err)
			}
			if gotProvider != nil {
				t.Fatalf("invariant violated: unauthenticated caller resolved a real provider: %+v", gotProvider)
			}
		})
	}

	// Control: the same explicit-provider request, now from a caller
	// ApiFilter has actually identified, must keep working exactly as
	// before — this is the legitimate SDK / frontend usage the fix must not
	// break (e.g. TestEmailWidget / upload flows that name a provider
	// explicitly for an already-authenticated user).
	t.Run("authenticated caller with explicit provider still resolves it", func(t *testing.T) {
		c := newSignedInApiController(base+"&fullFilePath=/idcard/victim/idfront.png&provider="+providerName, "niro-alpha/victim")

		gotProvider, err := c.GetProviderFromContext("Storage")
		if err != nil {
			t.Fatalf("expected an authenticated caller supplying an explicit provider to succeed, got error: %v", err)
		}
		if gotProvider == nil || gotProvider.Name != providerName {
			t.Fatalf("expected to resolve provider %q, got %+v", providerName, gotProvider)
		}
	})
}
