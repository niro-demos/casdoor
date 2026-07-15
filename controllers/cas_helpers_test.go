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
	"errors"
	"net"
	"testing"
)

func TestServiceMatchesIssuedService(t *testing.T) {
	tests := []struct {
		name          string
		service       string
		issuedService string
		want          bool
	}{
		{"exact match", "http://localhost:8000/callback", "http://localhost:8000/callback", true},
		{"string-extended service must not match", "http://localhost:8000/callback.attacker-controlled.example/steal", "http://localhost:8000/callback", false},
		{"unrelated service must not match", "http://evil.example.com/steal", "http://localhost:8000/callback", false},
		{"query-escaped exact match", "http%3A%2F%2Flocalhost%3A8000%2Fcallback", "http://localhost:8000/callback", true},
		{"trailing slash is not equivalent", "http://localhost:8000/callback/", "http://localhost:8000/callback", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serviceMatchesIssuedService(tt.service, tt.issuedService); got != tt.want {
				t.Errorf("serviceMatchesIssuedService(%q, %q) = %v, want %v", tt.service, tt.issuedService, got, tt.want)
			}
		})
	}
}

func TestIsProxyCallbackIPAllowed(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback v4", "127.0.0.1", false},
		{"loopback v6", "::1", false},
		{"unspecified", "0.0.0.0", false},
		{"private 10/8", "10.1.2.3", false},
		{"private 172.16/12", "172.16.5.5", false},
		{"private 192.168/16", "192.168.1.1", false},
		{"link-local", "169.254.1.1", false},
		{"cloud metadata", "169.254.169.254", false},
		{"public v4", "8.8.8.8", true},
		{"public v6", "2001:4860:4860::8888", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isProxyCallbackIPAllowed(net.ParseIP(tt.ip)); got != tt.want {
				t.Errorf("isProxyCallbackIPAllowed(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}

	t.Run("nil IP", func(t *testing.T) {
		if isProxyCallbackIPAllowed(nil) {
			t.Errorf("isProxyCallbackIPAllowed(nil) = true, want false")
		}
	})
}

func TestIsProxyCallbackHostAllowed(t *testing.T) {
	t.Run("IP-literal loopback host is rejected without a DNS lookup", func(t *testing.T) {
		resolveCalled := false
		fakeResolve := func(host string) ([]net.IP, error) {
			resolveCalled = true
			return nil, errors.New("should not be called for an IP literal")
		}
		allowed, err := isProxyCallbackHostAllowed("127.0.0.1", fakeResolve)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Errorf("expected loopback IP literal to be disallowed")
		}
		if resolveCalled {
			t.Errorf("resolver should not be invoked for an IP-literal host")
		}
	})

	t.Run("hostname resolving only to public addresses is allowed", func(t *testing.T) {
		fakeResolve := func(host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		allowed, err := isProxyCallbackHostAllowed("public.example.com", fakeResolve)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Errorf("expected a hostname resolving to a public address to be allowed")
		}
	})

	t.Run("hostname resolving to any private address is rejected", func(t *testing.T) {
		fakeResolve := func(host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")}, nil
		}
		allowed, err := isProxyCallbackHostAllowed("mixed.example.com", fakeResolve)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Errorf("expected a hostname with any private resolved address to be disallowed")
		}
	})

	t.Run("resolver error propagates", func(t *testing.T) {
		wantErr := errors.New("no such host")
		fakeResolve := func(host string) ([]net.IP, error) {
			return nil, wantErr
		}
		_, err := isProxyCallbackHostAllowed("does-not-exist.example.com", fakeResolve)
		if !errors.Is(err, wantErr) {
			t.Errorf("expected resolver error to propagate, got %v", err)
		}
	})
}
