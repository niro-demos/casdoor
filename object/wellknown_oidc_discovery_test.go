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
)

// Security invariant (TC-8EFF1BEE): the identity server must not build
// authoritative URLs (OIDC discovery issuer/endpoints, SAML SSO redirect
// Location) from the client-supplied Host header. Whatever the client sends as
// its Host, an attacker-chosen domain must never be echoed verbatim into an
// authoritative URL.
//
// The exploitable configuration is the shipped default, where "origin" is
// empty (conf/app.conf: `origin =`). In that state the old code fell through
// and built the origin directly from the raw Host header. These tests pin the
// invariant in exactly that default configuration: with no "origin" configured,
// an attacker Host must not be reflected into any authoritative URL.
//
// t.Setenv("origin", "") is read first by conf.GetConfigString via
// os.LookupEnv, so these tests deterministically exercise the empty-origin
// default without loading app.conf and without any DB.

const attackerHost = "evil.attacker.com"

// getOriginFromHost is the single choke point reused by both reachable sinks.
func TestGetOriginFromHost_DoesNotReflectAttackerHostWithDefaultOrigin(t *testing.T) {
	// Shipped default: origin unset.
	t.Setenv("origin", "")
	t.Setenv("originFrontend", "")

	frontend, backend := getOriginFromHost(attackerHost)
	if strings.Contains(frontend, attackerHost) || strings.Contains(backend, attackerHost) {
		t.Fatalf("VULNERABLE: attacker Host %q reflected into origin (frontend=%q backend=%q)",
			attackerHost, frontend, backend)
	}
}

// Control: an explicitly configured origin is always honored, regardless of the
// incoming Host. This proves the fix keeps the intended behavior when origin is
// set, so the red above is the invariant and not a broken environment.
func TestGetOriginFromHost_HonorsConfiguredOrigin(t *testing.T) {
	const configured = "https://id.example.com"
	t.Setenv("origin", configured)
	t.Setenv("originFrontend", "")

	frontend, backend := getOriginFromHost(attackerHost)
	if frontend != configured || backend != configured {
		t.Fatalf("expected configured origin %q for any Host, got frontend=%q backend=%q",
			configured, frontend, backend)
	}
}

// Sink 1: OIDC discovery document, default (empty) origin.
func TestGetOidcDiscovery_DoesNotReflectAttackerHostWithDefaultOrigin(t *testing.T) {
	t.Setenv("origin", "")
	t.Setenv("originFrontend", "")

	d := GetOidcDiscovery(attackerHost, "")
	authoritative := map[string]string{
		"issuer":                 d.Issuer,
		"authorization_endpoint": d.AuthorizationEndpoint,
		"token_endpoint":         d.TokenEndpoint,
		"userinfo_endpoint":      d.UserinfoEndpoint,
		"jwks_uri":               d.JwksUri,
		"end_session_endpoint":   d.EndSessionEndpoint,
		"introspection_endpoint": d.IntrospectionEndpoint,
	}
	for name, val := range authoritative {
		if strings.Contains(val, attackerHost) {
			t.Errorf("VULNERABLE: attacker Host %q reflected into OIDC %s = %q", attackerHost, name, val)
		}
	}
}

// Sink 2: SAML SSO redirect Location, default (empty) origin.
func TestGetSamlRedirectAddress_DoesNotReflectAttackerHostWithDefaultOrigin(t *testing.T) {
	t.Setenv("origin", "")
	t.Setenv("originFrontend", "")

	loc := GetSamlRedirectAddress("acme", "app-acme", "test", "abc", attackerHost, "", "")
	if strings.Contains(loc, attackerHost) {
		t.Fatalf("VULNERABLE: attacker Host %q reflected into SAML redirect Location: %q", attackerHost, loc)
	}
}
