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
	"net"
	"testing"
)

// TestIsDisallowedOutboundIP is the core invariant behind every SSRF finding in
// this cluster: the shared egress guard must classify loopback, private
// (RFC1918/RFC4193), link-local (incl. the 169.254.169.254 cloud-metadata
// address), unspecified, and multicast destinations as disallowed, while
// leaving ordinary public addresses allowed. Parametrized across the address
// families so a single invariant covers every sink that reuses the guard.
func TestIsDisallowedOutboundIP(t *testing.T) {
	cases := []struct {
		name       string
		ip         string
		disallowed bool
	}{
		{"ipv4 loopback", "127.0.0.1", true},
		{"ipv4 loopback range", "127.9.9.9", true},
		{"ipv6 loopback", "::1", true},
		{"cloud metadata 169.254.169.254", "169.254.169.254", true},
		{"link-local ipv4", "169.254.1.1", true},
		{"link-local ipv6", "fe80::1", true},
		{"rfc1918 10/8", "10.1.2.3", true},
		{"rfc1918 172.16/12", "172.16.5.5", true},
		{"rfc1918 192.168/16", "192.168.1.1", true},
		{"unique local ipv6 fc00::/7", "fd00::1", true},
		{"unspecified ipv4", "0.0.0.0", true},
		{"unspecified ipv6", "::", true},
		{"multicast", "224.0.0.1", true},
		{"public ipv4", "93.184.216.34", false},
		{"public ipv4 google dns", "8.8.8.8", false},
		{"public ipv6", "2606:2800:220:1:248:1893:25c8:1946", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("failed to parse test IP %q", tc.ip)
			}
			got := IsDisallowedOutboundIP(ip)
			if got != tc.disallowed {
				t.Fatalf("IsDisallowedOutboundIP(%s) = %v, want %v", tc.ip, got, tc.disallowed)
			}
		})
	}
}

// TestCheckOutboundHost asserts the string-level guard that every sink calls
// before dialing: a host whose literal IP or resolved address lands in a
// disallowed range is rejected, and a plainly public address is accepted.
func TestCheckOutboundHost(t *testing.T) {
	disallowedHosts := []string{
		"127.0.0.1",
		"127.0.0.1:8000",
		"localhost",
		"localhost:9999",
		"169.254.169.254",
		"[::1]:443",
		"10.0.0.5",
		"192.168.0.1",
		"172.16.0.1",
	}
	for _, host := range disallowedHosts {
		t.Run("reject/"+host, func(t *testing.T) {
			if err := CheckOutboundHost(host); err == nil {
				t.Fatalf("CheckOutboundHost(%q) = nil, want rejection of internal destination", host)
			}
		})
	}

	// A public IP literal must be allowed (no DNS needed, so this is stable in CI).
	allowedHosts := []string{
		"93.184.216.34",
		"8.8.8.8",
		"8.8.8.8:443",
	}
	for _, host := range allowedHosts {
		t.Run("allow/"+host, func(t *testing.T) {
			if err := CheckOutboundHost(host); err != nil {
				t.Fatalf("CheckOutboundHost(%q) = %v, want allow for public destination", host, err)
			}
		})
	}
}
