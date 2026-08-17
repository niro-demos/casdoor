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

package util

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetClientIpFromRequestIgnoresForgedHeaderFromUntrustedPeer is the
// regression test for TC-79558276: an unauthenticated caller connecting
// directly (i.e. not through any configured reverse proxy) can set
// X-Forwarded-For to an arbitrary address and have it accepted as the
// client's identity. Downstream code (resolveOpenClawProvider ->
// GetOpenClawProviderByIP) uses this value as if it were a trustworthy
// network-level credential to satisfy an IP allowlist, so a spoofed header
// here directly defeats that allowlist.
//
// The invariant under test: the client IP returned for a request whose
// direct peer is NOT a configured trusted proxy must be the request's real
// TCP peer address, never a value the caller supplied in a header.
func TestGetClientIpFromRequestIgnoresForgedHeaderFromUntrustedPeer(t *testing.T) {
	// Make sure no trusted proxy is configured for this scenario, regardless
	// of the ambient environment/app.conf.
	os.Unsetenv("trustedProxies")

	allowlistedIp := "203.0.113.5"
	realPeerAddr := "172.18.0.1:54321"

	req := httptest.NewRequest("POST", "/api/v1/traces", nil)
	req.RemoteAddr = realPeerAddr
	req.Header.Set("X-Forwarded-For", allowlistedIp)

	got := GetClientIpFromRequest(req)

	// RED (pre-fix): got == allowlistedIp, i.e. the attacker successfully
	// impersonated the allowlisted address.
	// GREEN (post-fix): got must be the real peer, never the forged header.
	assert.NotEqual(t, allowlistedIp, got, "an untrusted peer's forged X-Forwarded-For must not be trusted as the client IP")
	assert.Equal(t, "172.18.0.1", got, "client IP for an untrusted peer must fall back to the real TCP peer address")
}

// TestGetClientIpFromRequestHonorsHeaderFromTrustedProxy is the control: a
// legitimate deployment that sits behind a configured reverse proxy must
// keep working exactly as before -- the proxy's forwarded value is still
// honored, so real client IPs keep flowing into audit logs, rate limiting,
// and (for OpenClaw) the provider IP allowlist.
func TestGetClientIpFromRequestHonorsHeaderFromTrustedProxy(t *testing.T) {
	proxyAddr := "10.0.0.9"
	realClientIp := "198.51.100.7"

	os.Setenv("trustedProxies", proxyAddr)
	defer os.Unsetenv("trustedProxies")

	req := httptest.NewRequest("POST", "/api/v1/traces", nil)
	req.RemoteAddr = proxyAddr + ":443"
	req.Header.Set("X-Forwarded-For", realClientIp)

	got := GetClientIpFromRequest(req)

	assert.Equal(t, realClientIp, got, "a request relayed by a configured trusted proxy must still resolve to the forwarded client IP")
}
