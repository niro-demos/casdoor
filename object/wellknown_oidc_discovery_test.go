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

package object

import "testing"

// These tests cover TC-D12B1098: the OIDC discovery document and the `iss`
// claim placed in issued access/ID/refresh tokens must always reflect the
// server's actual configured origin, never an arbitrary value taken from the
// client-supplied HTTP Host header.
//
// getOriginFromHost/getOriginFromHostInternal is the single shared function
// both symptoms (discovery issuer at wellknown_oidc_discovery.go and the
// signed `iss` claim baked in by generateJwtToken at token_jwt.go:526) read
// from with no further transformation, so asserting its behavior directly
// proves both call sites are fixed.

// resetOriginEnv clears every env var that getOriginFromHost consults so
// each test starts from the documented shipped default (`origin =` unset)
// regardless of what the host environment happens to have set, and restores
// the previous values afterwards.
func resetOriginEnv(t *testing.T) {
	t.Helper()
	t.Setenv("origin", "")
	t.Setenv("originFrontend", "")
	t.Setenv("originAllowlist", "")
	t.Setenv("runmode", "prod")
}

func TestGetOriginFromHost_DoesNotReflectUnlistedDomainHost(t *testing.T) {
	resetOriginEnv(t)

	evilHost := "evil.attacker.com"
	gotFrontend, gotBackend := getOriginFromHost(evilHost)

	if gotFrontend == "https://"+evilHost || gotBackend == "https://"+evilHost {
		t.Fatalf("getOriginFromHost(%q) = (%q, %q), attacker-supplied Host header was reflected into the origin/issuer -- expected it to be rejected since it is neither the configured origin nor allow-listed", evilHost, gotFrontend, gotBackend)
	}
}

func TestGetOriginFromHost_LegitimateIpHostUnaffected(t *testing.T) {
	resetOriginEnv(t)

	// Positive control: an IP-literal host (how the harness/CI reaches the
	// server) must keep working exactly as before -- proving the rejection
	// above is about untrusted domain-name hosts, not a broken environment.
	legitHost := "127.0.0.1:18000"
	gotFrontend, gotBackend := getOriginFromHost(legitHost)

	wantOrigin := "http://" + legitHost
	if gotFrontend != wantOrigin || gotBackend != wantOrigin {
		t.Fatalf("getOriginFromHost(%q) = (%q, %q), want (%q, %q)", legitHost, gotFrontend, gotBackend, wantOrigin, wantOrigin)
	}
}

func TestGetOriginFromHost_ConfiguredOriginAlwaysWins(t *testing.T) {
	resetOriginEnv(t)
	t.Setenv("origin", "https://real-origin.example.com")

	gotFrontend, gotBackend := getOriginFromHost("evil.attacker.com")

	want := "https://real-origin.example.com"
	if gotFrontend != want || gotBackend != want {
		t.Fatalf("getOriginFromHost with configured origin = (%q, %q), want (%q, %q)", gotFrontend, gotBackend, want, want)
	}
}

func TestGetOriginFromHost_AllowlistedDomainHostIsTrusted(t *testing.T) {
	resetOriginEnv(t)
	t.Setenv("originAllowlist", "trusted.example.com,other.example.com")

	gotFrontend, gotBackend := getOriginFromHost("trusted.example.com")

	want := "https://trusted.example.com"
	if gotFrontend != want || gotBackend != want {
		t.Fatalf("getOriginFromHost(allow-listed host) = (%q, %q), want (%q, %q)", gotFrontend, gotBackend, want, want)
	}
}

func TestGetOidcDiscovery_IssuerDoesNotReflectSpoofedHost(t *testing.T) {
	resetOriginEnv(t)

	evilHost := "evil.attacker.com"
	discovery := GetOidcDiscovery(evilHost, "")

	if discovery.Issuer == "https://"+evilHost {
		t.Fatalf("GetOidcDiscovery(%q).Issuer = %q, discovery document reflected the attacker-supplied Host header", evilHost, discovery.Issuer)
	}
}

func TestGetOidcDiscovery_IssuerMatchesRealOriginForLegitimateHost(t *testing.T) {
	resetOriginEnv(t)

	legitHost := "127.0.0.1:18000"
	discovery := GetOidcDiscovery(legitHost, "")

	want := "http://" + legitHost
	if discovery.Issuer != want {
		t.Fatalf("GetOidcDiscovery(%q).Issuer = %q, want %q", legitHost, discovery.Issuer, want)
	}
}
