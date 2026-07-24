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
	"testing"
)

// Security invariant (TC-B8325909): the client-supplied X-Forwarded-For /
// X-Real-IP header must only be honored when the immediate connection
// (RemoteAddr) is a configured trusted proxy. Otherwise an unauthenticated
// caller can forge an arbitrary source IP — which the OTLP ingestion endpoints
// (and record/audit logging) use as an identity signal — by simply setting the
// header. GetClientIpFromRequest must fall back to the real RemoteAddr for any
// untrusted peer, regardless of what the caller claims in the header.
func TestGetClientIpFromRequest_ForgedForwardedForIsIgnored(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIp       string
		trusted       []string // trusted-proxy allowlist for this scenario
		want          string
	}{
		{
			// The exploit: a direct, untrusted internet caller forges the
			// header to impersonate a provider's Host IP. The forged value
			// MUST be discarded; the true peer address is used instead.
			name:          "forged XFF from untrusted peer is ignored",
			remoteAddr:    "192.168.65.1:54321",
			xForwardedFor: "203.0.113.201",
			trusted:       nil,
			want:          "192.168.65.1",
		},
		{
			name:       "forged X-Real-IP from untrusted peer is ignored",
			remoteAddr: "192.168.65.1:54321",
			xRealIp:    "203.0.113.201",
			trusted:    nil,
			want:       "192.168.65.1",
		},
		{
			// Legitimate reverse-proxy deployment: when the immediate peer IS
			// a configured trusted proxy, the forwarded client IP is honored.
			name:          "XFF from trusted proxy is honored",
			remoteAddr:    "10.0.0.9:443",
			xForwardedFor: "203.0.113.201",
			trusted:       []string{"10.0.0.9"},
			want:          "203.0.113.201",
		},
		{
			// Trusted proxy, multiple hops: the left-most (original client) wins.
			name:          "XFF chain from trusted proxy uses left-most",
			remoteAddr:    "10.0.0.9:443",
			xForwardedFor: "203.0.113.201, 10.0.0.9",
			trusted:       []string{"10.0.0.0/8"},
			want:          "203.0.113.201",
		},
		{
			// No header at all: RemoteAddr is used (baseline healthy path).
			name:       "no header falls back to RemoteAddr",
			remoteAddr: "198.51.100.7:1234",
			trusted:    nil,
			want:       "198.51.100.7",
		},
	}

	saved := GetTrustedProxies()
	defer SetTrustedProxies(saved)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SetTrustedProxies(tc.trusted)

			req, err := http.NewRequest("POST", "http://example/api/v1/traces", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.RemoteAddr = tc.remoteAddr
			if tc.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}
			if tc.xRealIp != "" {
				req.Header.Set("X-Real-IP", tc.xRealIp)
			}

			got := GetClientIpFromRequest(req)
			if got != tc.want {
				t.Fatalf("GetClientIpFromRequest() = %q, want %q "+
					"(remoteAddr=%q XFF=%q XRealIP=%q trusted=%v)",
					got, tc.want, tc.remoteAddr, tc.xForwardedFor, tc.xRealIp, tc.trusted)
			}
		})
	}
}
