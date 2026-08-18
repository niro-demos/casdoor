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
	"context"
	"net"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		addresses := map[string][]net.IPAddr{
			"public.example":  {{IP: net.ParseIP("8.8.8.8")}},
			"private.example": {{IP: net.ParseIP("10.0.0.8")}},
			"mixed.example": {
				{IP: net.ParseIP("8.8.8.8")},
				{IP: net.ParseIP("192.168.1.8")},
			},
		}
		return addresses[host], nil
	}

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "public IPv4 literal", url: "https://8.8.8.8/hook"},
		{name: "public DNS destination", url: "https://public.example/hook"},
		{name: "loopback IPv4", url: "http://127.0.0.1/hook", wantErr: true},
		{name: "private IPv4", url: "http://10.2.3.4/hook", wantErr: true},
		{name: "link-local IPv4", url: "http://169.254.169.254/latest/meta-data", wantErr: true},
		{name: "carrier-grade NAT IPv4", url: "http://100.64.0.1/hook", wantErr: true},
		{name: "documentation IPv4", url: "http://192.0.2.1/hook", wantErr: true},
		{name: "loopback IPv6", url: "http://[::1]/hook", wantErr: true},
		{name: "documentation IPv6", url: "http://[2001:db8::1]/hook", wantErr: true},
		{name: "IPv4-mapped private address", url: "http://[::ffff:10.2.3.4]/hook", wantErr: true},
		{name: "private DNS destination", url: "http://private.example/hook", wantErr: true},
		{name: "mixed public and private answers", url: "http://mixed.example/hook", wantErr: true},
		{name: "unsupported scheme", url: "file:///etc/passwd", wantErr: true},
		{name: "credentials in URL", url: "https://user:password@public.example/hook", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(context.Background(), tt.url, lookup)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateWebhookURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
