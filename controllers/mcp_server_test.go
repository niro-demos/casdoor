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
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// TestValidateServerUrlRejectsDisallowedAddresses is a regression test for
// TC-26A19235: ProxyServer must reject an MCP Server.Url whose host
// resolves to a loopback, link-local (including the cloud-metadata address
// 169.254.169.254), or private address, instead of letting
// httputil.ReverseProxy dial it. These are the same address classes the
// live PoC exercised (loopback 127.0.0.1 with a proxy dial error, and the
// Azure metadata address 169.254.169.254).
func TestValidateServerUrlRejectsDisallowedAddresses(t *testing.T) {
	cases := []string{
		"http://127.0.0.1:1/x",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://10.0.0.5/internal",
		"http://[::1]:8080/",
		"http://[fd00:ec2::254]/",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := validateServerUrl(raw); err == nil {
				t.Fatalf("validateServerUrl(%q) = nil error, want rejection of the disallowed address", raw)
			}
		})
	}
}

// TestValidateServerUrlAllowsPublicAddress is the positive control for
// TestValidateServerUrlRejectsDisallowedAddresses: a Server.Url whose host
// is a genuine public address must still validate successfully, proving the
// guard discriminates by address class rather than rejecting everything.
func TestValidateServerUrlAllowsPublicAddress(t *testing.T) {
	cases := []string{
		"http://93.184.216.34/",
		"https://8.8.8.8/mcp",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := validateServerUrl(raw); err != nil {
				t.Fatalf("validateServerUrl(%q) unexpected error: %v, want a public address to be allowed", raw, err)
			}
		})
	}
}

// TestValidateServerUrlPreservesExistingChecks confirms the pre-existing
// "is it an absolute http(s) URL with a host" validation still runs (this
// fix must not weaken it).
func TestValidateServerUrlPreservesExistingChecks(t *testing.T) {
	cases := []string{
		"not-a-url",
		"/relative/path",
		"ftp://93.184.216.34/",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := validateServerUrl(raw); err == nil {
				t.Fatalf("validateServerUrl(%q) = nil error, want rejection of the malformed/non-http(s) URL", raw)
			}
		})
	}
}

// TestSafeProxyDialContextBlocksLoopbackDestination is the TOCTOU/DNS-
// rebinding regression test: even if a URL host resolved safely at
// validation time, the transport that actually dials the connection must
// independently refuse a loopback/private/link-local destination. It uses a
// direct plain dial as a positive control to prove the address really was
// reachable, so the rejection below is provably the guard, not a broken
// test server.
func TestSafeProxyDialContextBlocksLoopbackDestination(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("test setup: could not parse httptest server URL: %v", err)
	}
	addr := parsed.Host // host:port, e.g. 127.0.0.1:PORT

	// Positive control: the address is genuinely dialable directly.
	directConn, dialErr := net.Dial("tcp", addr)
	if dialErr != nil {
		t.Fatalf("test setup: httptest server not reachable via a plain dial: %v", dialErr)
	}
	_ = directConn.Close()

	// Exploit path: the proxy's own dial context must refuse the same
	// loopback address instead of connecting to it.
	conn, err := safeProxyDialContext(context.Background(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("safeProxyDialContext(%q) succeeded dialing a loopback address, want rejection", addr)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("safeProxyDialContext dialed the loopback server (hits=%d); it must reject before connecting", hits)
	}
}
