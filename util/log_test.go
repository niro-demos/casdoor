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
	"net/http"
	"os"
	"testing"
)

// newRequest builds an *http.Request with a fixed real TCP peer (RemoteAddr)
// and an optional client-supplied X-Forwarded-For header.
func newRequest(remoteAddr, xff string) *http.Request {
	req, _ := http.NewRequest("POST", "http://example/api/v1/logs", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return req
}

// setTrustedProxies configures the trustedProxies value for the duration of a
// test via the environment (conf.GetConfigString consults the environment
// first), and restores it afterwards.
func setTrustedProxies(t *testing.T, value string) {
	t.Helper()
	prev, had := os.LookupEnv("trustedProxies")
	if err := os.Setenv("trustedProxies", value); err != nil {
		t.Fatalf("failed to set trustedProxies: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("trustedProxies", prev)
		} else {
			_ = os.Unsetenv("trustedProxies")
		}
	})
}

// TestGetClientIpFromRequest_XForwardedForSpoofing is the regression test for
// TC-1E80F373. Invariant: a client-supplied X-Forwarded-For header must NOT be
// able to override the request's real, TCP-observed source IP unless the
// immediate peer is a configured trusted proxy. This is what gates the
// unauthenticated OTLP ingestion endpoints (/api/v1/{logs,metrics,traces}) via
// resolveOpenClawProvider -> GetOpenClawProviderByIP, so spoofing it lets an
// unauthenticated caller impersonate another tenant's allow-listed IP.
func TestGetClientIpFromRequest_XForwardedForSpoofing(t *testing.T) {
	// No trusted proxies configured (the default deployment): the header must be
	// ignored entirely.
	setTrustedProxies(t, "")

	const (
		realPeer  = "192.168.65.1:52344" // the attacker's real TCP source
		allowedIP = "10.10.10.10"        // a victim tenant's allow-listed IP
	)

	// Control: a legitimate direct request with no forged header resolves to the
	// real peer IP. Proves the resolver works and the environment is healthy.
	if got := GetClientIpFromRequest(newRequest(realPeer, "")); got != "192.168.65.1" {
		t.Fatalf("control (no XFF): expected real peer 192.168.65.1, got %q", got)
	}

	// INVARIANT: a forged X-Forwarded-For claiming the victim's allow-listed IP
	// must NOT be honored, because the real peer is not a trusted proxy. The
	// resolver must return the real peer IP, not the spoofed value.
	got := GetClientIpFromRequest(newRequest(realPeer, allowedIP))
	if got == allowedIP {
		t.Fatalf("INVARIANT VIOLATED: forged X-Forwarded-For %q overrode the real "+
			"TCP source %q; an unauthenticated caller could impersonate another "+
			"tenant's allow-listed OpenClaw provider IP", allowedIP, realPeer)
	}
	if got != "192.168.65.1" {
		t.Fatalf("expected real peer 192.168.65.1 (forged XFF ignored), got %q", got)
	}

	// INVARIANT (unrelated spoof): forging an arbitrary IP must likewise be
	// ignored — acceptance is never keyed on the presence of any XFF header.
	if got := GetClientIpFromRequest(newRequest(realPeer, "198.51.100.234")); got != "192.168.65.1" {
		t.Fatalf("forged unrelated XFF was honored: expected 192.168.65.1, got %q", got)
	}
}

// TestGetClientIpFromRequest_TrustedProxyHonored proves the fix is not a blunt
// "always ignore XFF": when the immediate peer IS a configured trusted proxy,
// the forwarded client IP is honored, so legitimate reverse-proxy deployments
// still see the real client IP.
func TestGetClientIpFromRequest_TrustedProxyHonored(t *testing.T) {
	setTrustedProxies(t, "192.168.65.1, 10.0.0.0/8")

	// Peer is the trusted proxy 192.168.65.1 -> honor the forwarded client IP.
	if got := GetClientIpFromRequest(newRequest("192.168.65.1:41000", "203.0.113.7")); got != "203.0.113.7" {
		t.Fatalf("trusted proxy: expected forwarded client IP 203.0.113.7, got %q", got)
	}

	// Peer inside a trusted CIDR -> honor the forwarded client IP.
	if got := GetClientIpFromRequest(newRequest("10.1.2.3:41000", "203.0.113.9")); got != "203.0.113.9" {
		t.Fatalf("trusted CIDR: expected forwarded client IP 203.0.113.9, got %q", got)
	}

	// Peer NOT in the trusted set -> ignore the header, use the real peer.
	if got := GetClientIpFromRequest(newRequest("172.16.0.5:41000", "203.0.113.9")); got != "172.16.0.5" {
		t.Fatalf("untrusted peer: expected real peer 172.16.0.5, got %q", got)
	}
}
