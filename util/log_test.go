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
	"testing"
)

func TestGetClientIpFromRequestIgnoresUntrustedForwardedFor(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "direct request uses network peer",
			remoteAddr: "172.18.0.1:54321",
			xff:        "198.51.100.77",
			want:       "172.18.0.1",
		},
		{
			name:       "direct request without forwarded header still uses network peer",
			remoteAddr: "172.18.0.1:54321",
			want:       "172.18.0.1",
		},
		{
			name:       "ipv6 peer with forged forwarded header still uses network peer",
			remoteAddr: "[2001:db8::1]:54321",
			xff:        "198.51.100.77",
			want:       "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/logs", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			if got := GetClientIpFromRequest(req); got != tt.want {
				t.Fatalf("GetClientIpFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}
