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

	"github.com/stretchr/testify/assert"
)

// TestGetClientIpFromRequest_IgnoresSpoofedXFFWithoutTrustedProxy is the
// regression test for TC-990A9982: GetClientIpFromRequest is used by
// controllers/entry_util.go resolveOpenClawProvider() as the sole
// authentication check that gates the unauthenticated OTLP ingestion
// endpoints (/api/v1/traces|metrics|logs). Because it read the
// client-supplied X-Forwarded-For header unconditionally, any caller could
// forge that header to impersonate a configured agent's trusted IP with no
// credential at all.
//
// Invariant under test: a caller who merely CLAIMS (via X-Forwarded-For) to
// be a trusted address must NOT be treated as that address unless the
// request's actual TCP peer (RemoteAddr) is itself a configured trusted
// proxy. With no trusted proxy configured (the default, and the harness
// environment's actual topology), the header must be ignored entirely and
// the real peer address used instead.
func TestGetClientIpFromRequest_IgnoresSpoofedXFFWithoutTrustedProxy(t *testing.T) {
	// Make sure no trustedProxies value leaks in from the environment.
	os.Unsetenv("trustedProxies")

	req, err := http.NewRequest("POST", "http://example.com/api/v1/traces", nil)
	assert.Nil(t, err)
	req.RemoteAddr = "203.0.113.5:54321"
	req.Header.Set("X-Forwarded-For", "10.66.1.1") // forged, claims to be the trusted agent

	// The attacker's forged header must be ignored: the real peer IP
	// (RemoteAddr) is what gets returned, not the spoofed claim.
	assert.Equal(t, "203.0.113.5", GetClientIpFromRequest(req))
}

// TestGetClientIpFromRequest_HonorsXFFFromTrustedProxy is the control case:
// once an operator explicitly configures a reverse proxy as trusted (via the
// trustedProxies allowlist), a request whose real peer *is* that proxy still
// has its X-Forwarded-For value honored, so legitimate deployments behind a
// real reverse proxy keep working.
func TestGetClientIpFromRequest_HonorsXFFFromTrustedProxy(t *testing.T) {
	os.Setenv("trustedProxies", "203.0.113.5")
	defer os.Unsetenv("trustedProxies")

	req, err := http.NewRequest("POST", "http://example.com/api/v1/traces", nil)
	assert.Nil(t, err)
	req.RemoteAddr = "203.0.113.5:54321" // the configured trusted proxy
	req.Header.Set("X-Forwarded-For", "198.51.100.9")

	assert.Equal(t, "198.51.100.9", GetClientIpFromRequest(req))
}

// TestGetClientIpFromRequest_IgnoresXFFFromUntrustedPeerEvenWithAllowlistSet
// proves the allowlist is a real allowlist, not a global switch: a peer that
// is NOT in the configured trustedProxies list still cannot inject a
// forwarded IP, even though some proxy is trusted elsewhere in the config.
func TestGetClientIpFromRequest_IgnoresXFFFromUntrustedPeerEvenWithAllowlistSet(t *testing.T) {
	os.Setenv("trustedProxies", "203.0.113.5")
	defer os.Unsetenv("trustedProxies")

	req, err := http.NewRequest("POST", "http://example.com/api/v1/traces", nil)
	assert.Nil(t, err)
	req.RemoteAddr = "198.51.100.77:1111" // NOT the configured trusted proxy
	req.Header.Set("X-Forwarded-For", "10.66.1.1")

	assert.Equal(t, "198.51.100.77", GetClientIpFromRequest(req))
}
