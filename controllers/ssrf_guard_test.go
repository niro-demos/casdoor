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
	"testing"
)

// TestValidateProxyCallbackURL covers TC-44CE139A: the CAS serviceValidate
// pgtUrl callback must not let any authenticated user direct the server's own
// outbound verification request to an internal / loopback / link-local /
// cloud-metadata address. validateProxyCallbackURL is the gate CasP3ProxyValidate
// applies to the caller-supplied pgtUrl before dialing.
func TestValidateProxyCallbackURL(t *testing.T) {
	rejected := []string{
		"https://169.254.169.254/latest/meta-data/",
		"https://localhost:9999/",
		"https://127.0.0.1/callback",
		"https://10.0.0.5/callback",
		"https://192.168.1.1/callback",
		"https://[::1]/callback",
	}
	for _, u := range rejected {
		t.Run("reject/"+u, func(t *testing.T) {
			if err := validateProxyCallbackURL(u); err == nil {
				t.Fatalf("validateProxyCallbackURL(%q) = nil, want rejection of internal callback", u)
			}
		})
	}

	// Positive control: a public HTTPS callback must still be accepted, proving
	// the rejection is about the internal destination, not a broken validator. A
	// public IP literal is used so the control needs no DNS in CI.
	if err := validateProxyCallbackURL("https://8.8.8.8/proxyCallback"); err != nil {
		t.Fatalf("validateProxyCallbackURL(public) = %v, want accept", err)
	}
}

// TestValidateProxyTargetURL covers TC-E5E88ED8 (per-server reverse-proxy
// primitive): ProxyServer must not reverse-proxy to a server whose URL resolves
// to an internal / loopback / private / link-local destination. This is the
// egress gate ProxyServer applies before building the reverse proxy.
func TestValidateProxyTargetURL(t *testing.T) {
	rejected := []string{
		"http://127.0.0.1:8000/api/get-organizations",
		"http://localhost:8000/",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/",
		"http://192.168.1.1/",
		"http://[::1]:8000/",
	}
	for _, u := range rejected {
		t.Run("reject/"+u, func(t *testing.T) {
			if err := validateProxyTargetURL(u); err == nil {
				t.Fatalf("validateProxyTargetURL(%q) = nil, want rejection of internal upstream", u)
			}
		})
	}

	// Public IP literal positive control (no DNS needed in CI).
	if err := validateProxyTargetURL("https://8.8.8.8/mcp"); err != nil {
		t.Fatalf("validateProxyTargetURL(public) = %v, want accept", err)
	}
}
