// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

import "testing"

// TestValidateWebhookUrlRejectsReservedDestinations covers every destination
// class the finding's remediation guidance calls out: loopback, link-local
// (including the AWS/GCP/Azure cloud-metadata IP 169.254.169.254), IPv6
// loopback, and RFC1918/RFC4193 private ranges. Each must be rejected at
// webhook create/update time.
func TestValidateWebhookUrlRejectsReservedDestinations(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"aws-cloud-metadata", "http://169.254.169.254/latest/meta-data/"},
		{"gcp-cloud-metadata", "http://169.254.169.254/computeMetadata/v1/"},
		{"ipv4-loopback", "http://127.0.0.1:2379/v2/keys"},
		{"ipv6-loopback", "http://[::1]:8000/api/get-organizations"},
		{"rfc1918-10", "http://10.0.0.5:6379/"},
		{"rfc1918-172", "http://172.16.0.1/"},
		{"rfc1918-192", "http://192.168.1.1/"},
		{"link-local-other", "http://169.254.1.1/"},
		{"unspecified-v4", "http://0.0.0.0/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateWebhookUrl(tc.url); err == nil {
				t.Fatalf("validateWebhookUrl(%q) = nil, want a rejection error", tc.url)
			}
		})
	}
}

// TestValidateWebhookUrlAcceptsPublicDestination is the paired positive
// control: ordinary external destinations (public IP literals, so the check
// is deterministic without relying on DNS/internet access in the test
// environment) must still be accepted. This proves validateWebhookUrl blocks
// the specific reserved-address classes, not URLs in general.
func TestValidateWebhookUrlAcceptsPublicDestination(t *testing.T) {
	cases := []string{
		"https://93.184.216.34/webhook-callback",
		"http://1.1.1.1/webhook",
	}

	for _, u := range cases {
		if err := validateWebhookUrl(u); err != nil {
			t.Fatalf("validateWebhookUrl(%q) = %v, want nil (legitimate public destination)", u, err)
		}
	}
}

func TestValidateWebhookUrlRejectsNonHttpScheme(t *testing.T) {
	if err := validateWebhookUrl("file:///etc/passwd"); err == nil {
		t.Fatal("validateWebhookUrl should reject non-http(s) schemes")
	}
}

func TestValidateWebhookUrlRejectsEmpty(t *testing.T) {
	if err := validateWebhookUrl(""); err == nil {
		t.Fatal("validateWebhookUrl should reject an empty url")
	}
}
