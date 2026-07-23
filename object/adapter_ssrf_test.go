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

// TestInitAdapterRejectsInternalHost covers TC-10C14000: an org admin creating a
// Casbin policy adapter must not be able to make the server open outbound TCP
// connections to arbitrary internal hosts/ports. InitAdapter is the point where
// the attacker-controlled Host/Port are handed to the DB driver's dialer, so the
// egress guard must reject the internal host before xorm.NewEngine dials it.
//
// A non-builtin adapter (UseSameDb=false, owner != "built-in") with an internal
// Host must fail with a validation error rather than dialing the target — no DB
// connection is required for the guard to fire.
func TestInitAdapterRejectsInternalHost(t *testing.T) {
	// Loopback targets connect/refuse fast on the unfixed code, so the RED is
	// quick and provably about the guard being wired into InitAdapter. The full
	// disallowed-range matrix is asserted instantly in
	// util.TestIsDisallowedOutboundIP / util.TestCheckOutboundHost.
	// A single loopback closed port: on the unfixed code the mysql driver dials
	// and returns "connection refused" near-instantly, so the RED is fast and
	// provably about the guard being wired into InitAdapter. The full
	// disallowed-range matrix is asserted instantly in
	// util.TestIsDisallowedOutboundIP / util.TestCheckOutboundHost.
	cases := []struct {
		name string
		host string
		port int
	}{
		{"loopback closed port", "127.0.0.1", 9999},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &Adapter{
				Owner:        "org-alpha",
				Name:         "ssrf-test-adapter",
				DatabaseType: "mysql",
				Host:         tc.host,
				Port:         tc.port,
				User:         "root",
				Password:     "x",
				Database:     "mysql",
			}

			err := adapter.InitAdapter()
			if err == nil {
				t.Fatalf("InitAdapter with internal host %s:%d returned nil error; expected the host to be rejected before dialing", tc.host, tc.port)
			}
			// The error must be the egress rejection, not a raw dial error that
			// still leaks the connect result (which is the vulnerability).
			if strings.Contains(strings.ToLower(err.Error()), "connect: connection refused") ||
				strings.Contains(strings.ToLower(err.Error()), "dial tcp") {
				t.Fatalf("InitAdapter dialed the internal host (leaked raw socket result): %v", err)
			}
		})
	}
}
