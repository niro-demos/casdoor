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
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Invariant under test: "An organization admin must not be able to use the
// Casdoor server itself to probe arbitrary internal network hosts and ports
// and learn whether they are open, closed, or reachable."
//
// TC-BDBFFE41: /api/test-syncer-db (object.TestSyncer) took client-supplied
// host/port straight to a raw TCP/DB dial with no destination validation and
// no dial timeout, letting an org-scoped (non-global) admin use the server as
// an internal port scanner.

// TestValidateSyncerHostBlocksInternalRangesForNonGlobalAdmin covers the
// destination allowlist/denylist itself: loopback, RFC1918, and link-local
// (including the 169.254.169.254 cloud metadata address) must be rejected for
// a non-global-admin caller, and allowed for a global admin. Public hosts must
// never be blocked. All cases use literal IPs so resolution is local and the
// test needs no network access.
func TestValidateSyncerHostBlocksInternalRangesForNonGlobalAdmin(t *testing.T) {
	cases := []struct {
		name          string
		host          string
		isGlobalAdmin bool
		wantErr       bool
	}{
		{"loopback blocked for org admin", "127.0.0.1", false, true},
		{"rfc1918 10/8 blocked for org admin", "10.0.0.5", false, true},
		{"rfc1918 172.16/12 blocked for org admin", "172.16.0.5", false, true},
		{"rfc1918 192.168/16 blocked for org admin", "192.168.1.5", false, true},
		{"link-local / cloud metadata blocked for org admin", "169.254.169.254", false, true},
		{"public host allowed for org admin", "8.8.8.8", false, false},
		{"loopback allowed for global admin", "127.0.0.1", true, false},
		{"rfc1918 allowed for global admin", "10.0.0.5", true, false},
		{"metadata address allowed for global admin", "169.254.169.254", true, false},
		{"empty host is a no-op", "", false, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateSyncerHost(c.host, c.isGlobalAdmin)
			if c.wantErr && err == nil {
				t.Fatalf("validateSyncerHost(%q, isGlobalAdmin=%v) = nil, want a restricted-destination error", c.host, c.isGlobalAdmin)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("validateSyncerHost(%q, isGlobalAdmin=%v) = %v, want nil", c.host, c.isGlobalAdmin, err)
			}
		})
	}
}

// TestTestSyncerRejectsLoopbackForNonGlobalAdmin exercises the real entry
// point the controller calls (object.TestSyncer), reproducing the PoC's
// exact shape: an org-scoped admin pointing a "mysql" syncer test at
// 127.0.0.1. Owner/Name are left empty so getSyncer() short-circuits before
// touching the database (see getSyncer: owner=="" || name=="" -> nil, nil) --
// this test exercises only the SSRF guard, not persistence.
//
// On the unfixed code, TestSyncer dials straight through to the (closed)
// port and returns a driver/network error -- proving the request was never
// rejected on destination grounds. On the fixed code, it must be rejected
// immediately by the host guard, before any dial is attempted.
func TestTestSyncerRejectsLoopbackForNonGlobalAdmin(t *testing.T) {
	syncer := Syncer{
		DatabaseType: "mysql",
		Host:         "127.0.0.1",
		Port:         65533, // arbitrary local port, expected closed in the test sandbox
		User:         "root",
		Password:     "x",
		Database:     "test",
	}

	err := TestSyncer(syncer, false) // org-scoped (non-global) admin, matches acme-admin in the PoC
	if err == nil {
		t.Fatal("expected TestSyncer to reject a loopback destination for a non-global-admin caller, got nil error")
	}
	if !strings.Contains(err.Error(), "restricted") {
		t.Fatalf("expected a host-validation rejection (containing \"restricted\"), got a different error -- likely a real network dial was attempted instead of being blocked: %v", err)
	}
}

// TestTestSyncerAllowsLoopbackForGlobalAdmin proves the guard is scoped to
// non-global-admins only: a global admin (trusted to point syncers at
// internal infrastructure, the primary legitimate use of this feature) must
// not be blocked by the destination check. The dial itself will still fail
// (nothing listens on the port), but that failure must be a real network
// error, not our validation rejection.
func TestTestSyncerAllowsLoopbackForGlobalAdmin(t *testing.T) {
	syncer := Syncer{
		DatabaseType: "mysql",
		Host:         "127.0.0.1",
		Port:         65533,
		User:         "root",
		Password:     "x",
		Database:     "test",
	}

	err := TestSyncer(syncer, true) // global admin
	if err == nil {
		t.Fatal("expected a connection error against a closed port, got nil")
	}
	if strings.Contains(err.Error(), "restricted") {
		t.Fatalf("global admin should not be blocked by the destination guard, got: %v", err)
	}
}

// TestTestSyncerBoundsHangingConnectionWithTimeout reproduces the timing
// oracle itself: a listener that accepts TCP connections but never completes
// a protocol handshake (standing in for "any open internal port" per the
// PoC, e.g. Casdoor's own HTTP port). Without a bounded dial/handshake
// timeout, TestSyncer would hang indefinitely waiting for a handshake that
// never comes -- exactly the open-vs-closed timing oracle the finding
// describes. The test shrinks syncerTestConnectionTimeout so it doesn't
// itself take multiple seconds to run.
func TestTestSyncerBoundsHangingConnectionWithTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and hold the connection open, but never write the
			// handshake bytes a real DB client would wait for -- this is
			// what makes an open-but-unresponsive port indistinguishable
			// from a slow one without a bounded timeout.
			_ = conn
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse listener address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse listener port: %v", err)
	}

	oldTimeout := syncerTestConnectionTimeout
	syncerTestConnectionTimeout = 300 * time.Millisecond
	defer func() { syncerTestConnectionTimeout = oldTimeout }()

	syncer := Syncer{
		DatabaseType: "mysql",
		Host:         host,
		Port:         port,
		User:         "root",
		Password:     "x",
		Database:     "test",
	}

	start := time.Now()
	err = TestSyncer(syncer, true) // global admin: host allowed, so this exercises the dial-timeout path
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected TestSyncer to time out against a hung connection, got nil error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("TestSyncer took %v to return; expected it to be bounded by ~%v, not hang indefinitely", elapsed, syncerTestConnectionTimeout)
	}
}
