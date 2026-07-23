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

// TestGetOriginFromHostInternal_HostHeaderCannotControlIssuer asserts the
// security invariant that a caller's raw HTTP `Host` header must NOT control the
// issuer / endpoint origin the server bakes into its signed `iss` claim
// (object/token_jwt.go generateJwtToken) and its public OIDC discovery document
// (GetOidcDiscovery). When no canonical `origin` is configured,
// getOriginFromHostInternal must never echo an unvalidated, attacker-supplied
// Host: it either honors the configured origin, permits the fixed local-dev
// host, or fails closed (panics) — but it never returns the attacker's Host.
//
// conf.GetConfigString reads env vars first (os.LookupEnv), so t.Setenv fully
// controls `origin` and `runmode` without any DB or live server.
func TestGetOriginFromHostInternal_HostHeaderCannotControlIssuer(t *testing.T) {
	const attackerHost = "evil.attacker.com"

	t.Run("configured origin is honored regardless of Host (green control)", func(t *testing.T) {
		t.Setenv("origin", "https://sso.example.com")
		t.Setenv("runmode", "prod")

		originF, originB := getOriginFromHostInternal(attackerHost)
		if originF != "https://sso.example.com" || originB != "https://sso.example.com" {
			t.Fatalf("configured origin not honored: originF=%q originB=%q", originF, originB)
		}
	})

	t.Run("legitimate dev localhost still works (green control)", func(t *testing.T) {
		t.Setenv("origin", "")
		t.Setenv("runmode", "dev")

		originF, originB := getOriginFromHostInternal("localhost:8000")
		if !strings.Contains(originB, "localhost") {
			t.Fatalf("legitimate dev localhost broke: originF=%q originB=%q", originF, originB)
		}
	})

	// The core invariant: with no configured origin, an arbitrary attacker Host
	// header must NOT be echoed into the issuer/backend origin. The vulnerable
	// code returned "https://evil.attacker.com"; the fixed code fails closed
	// (panics) rather than trust the untrusted Host — in both non-dev runmode
	// and in dev runmode for any host other than the fixed local dev host.
	invariantCases := []struct {
		name    string
		runmode string
	}{
		{"non-dev runmode", "prod"},
		{"dev runmode", "dev"}, // even in dev, a non-localhost attacker Host must not be trusted
	}
	for _, tc := range invariantCases {
		t.Run("attacker Host does not reach issuer origin ("+tc.name+")", func(t *testing.T) {
			t.Setenv("origin", "")
			t.Setenv("runmode", tc.runmode)

			originF, originB := callAndRecoverOrigin(t, attackerHost)
			if strings.Contains(originF, attackerHost) || strings.Contains(originB, attackerHost) {
				t.Fatalf("INVARIANT VIOLATED: attacker Host %q leaked into issuer origin: originF=%q originB=%q",
					attackerHost, originF, originB)
			}
		})
	}
}

// callAndRecoverOrigin invokes getOriginFromHostInternal and, if it fails closed
// by panicking (the fixed behavior), reports empty origins so the caller can
// assert the attacker Host never leaked. If the function returns normally (the
// vulnerable behavior), its return values are surfaced verbatim so a leaked
// attacker Host is caught.
func callAndRecoverOrigin(t *testing.T, host string) (originF, originB string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			// Fail-closed: nothing was returned to a caller, so nothing leaked.
			originF, originB = "", ""
		}
	}()
	originF, originB = getOriginFromHostInternal(host)
	return originF, originB
}
