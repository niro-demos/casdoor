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

//go:build !skipCi

package controllers

import (
	"net/http"
	"testing"
)

func TestGetOpenClawClientIPUsesTcpPeerUnlessProxyTrusted(t *testing.T) {
	tests := []struct {
		name                 string
		remoteAddr           string
		xForwardedFor        string
		trustedProxyCidrs    string
		expectedClientIP     string
		expectedForwardedUse bool
	}{
		{
			name:             "untrusted peer cannot spoof provider identity",
			remoteAddr:       "172.18.0.1:45678",
			xForwardedFor:    "198.51.100.77, 203.0.113.24",
			expectedClientIP: "172.18.0.1",
		},
		{
			name:                 "trusted proxy can forward client identity",
			remoteAddr:           "10.0.0.7:45678",
			xForwardedFor:        "198.51.100.77, 203.0.113.24",
			trustedProxyCidrs:    "10.0.0.0/24",
			expectedClientIP:     "198.51.100.77",
			expectedForwardedUse: true,
		},
		{
			name:             "tcp peer remains the legitimate no-header control",
			remoteAddr:       "198.51.100.77:45678",
			expectedClientIP: "198.51.100.77",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("otlpTrustedProxyCidrs", tt.trustedProxyCidrs)

			req, err := http.NewRequest(http.MethodPost, "/api/v1/traces", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}

			clientIP, usedForwarded := getOpenClawClientIP(req)
			if clientIP != tt.expectedClientIP {
				t.Fatalf("client IP = %q, want %q", clientIP, tt.expectedClientIP)
			}
			if usedForwarded != tt.expectedForwardedUse {
				t.Fatalf("used forwarded header = %t, want %t", usedForwarded, tt.expectedForwardedUse)
			}
		})
	}
}
