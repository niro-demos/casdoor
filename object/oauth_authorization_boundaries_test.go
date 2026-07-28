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
)

func TestCanGrantConsentRequiresUserApplicationTenantMatch(t *testing.T) {
	alphaUser := &User{Owner: "alpha", Name: "alice"}
	alphaApp := &Application{Owner: "admin", Name: "app-alpha", Organization: "alpha"}
	betaApp := &Application{Owner: "admin", Name: "app-beta", Organization: "beta"}

	if !CanGrantConsentToApplication(alphaUser, alphaApp) {
		t.Fatal("same-tenant user should be allowed to grant consent")
	}

	if CanGrantConsentToApplication(alphaUser, betaApp) {
		t.Fatal("cross-tenant user must not be allowed to grant consent")
	}
}

func TestCanIntrospectTokenRequiresSameApplication(t *testing.T) {
	alphaApp := &Application{Owner: "admin", Name: "app-alpha", Organization: "alpha"}
	alphaToken := &Token{Owner: "admin", Application: "app-alpha", Organization: "alpha", User: "alice"}
	betaApp := &Application{Owner: "admin", Name: "app-beta", Organization: "beta"}

	if !CanIntrospectToken(alphaApp, alphaToken) {
		t.Fatal("an OAuth client should introspect its own token")
	}

	if CanIntrospectToken(betaApp, alphaToken) {
		t.Fatal("a different OAuth client must not introspect token metadata")
	}
}

func TestTokenScopeIntersectsConsentRevocation(t *testing.T) {
	token := &Token{Scope: "openid profile email"}

	if !TokenScopeIntersects(token, []string{"profile"}) {
		t.Fatal("revoking a granted scope should match issued tokens containing that scope")
	}

	if TokenScopeIntersects(token, []string{"address"}) {
		t.Fatal("revoking an unrelated scope should not match this token")
	}
}

func TestDeviceAuthCacheUsesConfiguredExpiry(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	cache := DeviceAuthCache{
		RequestAt: now.Add(-3 * time.Second),
		ExpiresIn: 2,
	}

	if !IsDeviceAuthExpired(cache, now) {
		t.Fatal("device authorization must expire after the configured per-request lifetime")
	}

	cache.ExpiresIn = 0
	if IsDeviceAuthExpired(cache, now) {
		t.Fatal("zero configured lifetime should fall back to the default device authorization lifetime")
	}
}
