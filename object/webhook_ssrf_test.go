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
	"net/http"
	"testing"
)

func TestValidateWebhookURLRejectsInternalTargets(t *testing.T) {
	tests := []string{
		"http://127.0.0.1:8080/callback",
		"http://[::1]/callback",
		"http://10.0.0.1/callback",
		"http://169.254.169.254/latest/meta-data/",
	}

	for _, target := range tests {
		if err := validateWebhookURL(context.Background(), target, net.DefaultResolver.LookupIPAddr); err == nil {
			t.Errorf("validateWebhookURL(%q) accepted an internal target", target)
		}
	}

	// Positive control: a syntactically valid public target remains supported.
	if err := validateWebhookURL(context.Background(), "https://8.8.8.8/callback", net.DefaultResolver.LookupIPAddr); err != nil {
		t.Fatalf("validateWebhookURL() rejected a public target: %v", err)
	}
}

func TestWebhookPersistenceAndDeliveryRejectLoopback(t *testing.T) {
	webhook := &Webhook{
		Owner:       "admin",
		Name:        "loopback",
		Url:         "http://127.0.0.1:1/callback",
		Method:      "POST",
		ContentType: "application/json",
	}

	if _, err := AddWebhook(webhook); err == nil {
		t.Fatal("AddWebhook() accepted a loopback target")
	}
	if _, _, err := sendWebhook(webhook, &Record{}, nil); err == nil {
		t.Fatal("sendWebhook() attempted delivery to a loopback target")
	}
}

func TestResolveWebhookDialAddressPreventsDNSRebinding(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host == "rebinding.example" {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}

	if _, err := resolveWebhookDialAddress(context.Background(), "tcp", "rebinding.example:443", lookup); err == nil {
		t.Fatal("resolveWebhookDialAddress() accepted a hostname that resolved to loopback")
	}

	address, err := resolveWebhookDialAddress(context.Background(), "tcp", "public.example:443", lookup)
	if err != nil {
		t.Fatalf("resolveWebhookDialAddress() rejected a public target: %v", err)
	}
	if address != "8.8.8.8:443" {
		t.Fatalf("resolveWebhookDialAddress() = %q, want %q", address, "8.8.8.8:443")
	}
}

func TestWebhookClientRejectsInternalRedirect(t *testing.T) {
	client := newWebhookHTTPClient()
	redirect, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(redirect, nil); err == nil {
		t.Fatal("webhook client accepted a redirect target on loopback")
	}
}
