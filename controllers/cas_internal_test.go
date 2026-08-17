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
	"net/url"
	"testing"
)

// TestIsPgtUrlHostAllowed exercises the SSRF guard added for TC-6E15E611
// directly, across the boundary the finding's remediation guidance calls
// out by name: loopback, RFC1918 private ranges, link-local (including the
// 169.254.0.0/16 cloud metadata range), and a routable public address. All
// cases use literal IP hosts so the test stays hermetic (no DNS lookups,
// no network access required).
func TestIsPgtUrlHostAllowed(t *testing.T) {
	cases := []struct {
		name    string
		pgtUrl  string
		allowed bool
	}{
		{"loopback", "https://127.0.0.1:8443/callback", false},
		{"rfc1918-10", "https://10.0.0.5:8443/callback", false},
		{"rfc1918-172", "https://172.16.0.5:8443/callback", false},
		{"rfc1918-192", "https://192.168.1.5:8443/callback", false},
		{"link-local-metadata", "https://169.254.169.254/latest/meta-data/", false},
		{"public-ip", "https://8.8.8.8:8443/callback", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.pgtUrl)
			if err != nil {
				t.Fatalf("failed to parse test pgtUrl %q: %v", tc.pgtUrl, err)
			}
			got := isPgtUrlHostAllowed(u)
			if got != tc.allowed {
				t.Fatalf("isPgtUrlHostAllowed(%q) = %v, want %v", tc.pgtUrl, got, tc.allowed)
			}
		})
	}
}
