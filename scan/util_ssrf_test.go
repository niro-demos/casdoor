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

package scan

import (
	"strings"
	"testing"
)

// TestNormalizeScanBaseURLRejectsInternalTargets covers TC-678B1A5A: a
// tenant-scoped admin configuring a "Security Scan"/"Url" provider must not be
// able to point the scan target at the server's own loopback / link-local /
// private ranges. normalizeScanBaseURL is the single validation gate before the
// scanner issues any outbound HTTP request, so the guard belongs here.
func TestNormalizeScanBaseURLRejectsInternalTargets(t *testing.T) {
	internalTargets := []string{
		"http://127.0.0.1:8000/api/get-account",
		"http://localhost:8000/",
		"https://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/",
		"http://192.168.1.1/",
		"http://[::1]:8000/",
		// no-scheme form: normalizeScanBaseURL defaults to https:// then must
		// still reject the internal host.
		"127.0.0.1:8000",
	}
	for _, target := range internalTargets {
		t.Run("reject/"+target, func(t *testing.T) {
			_, _, err := normalizeScanBaseURL(target)
			if err == nil {
				t.Fatalf("normalizeScanBaseURL(%q) = nil error, want rejection of internal target", target)
			}
		})
	}
}

// Positive control: a legitimate public target must still normalize cleanly, so
// the rejection above is provably about the internal address, not a broken
// validator.
func TestNormalizeScanBaseURLAllowsPublicTarget(t *testing.T) {
	// A public IP literal is used so the control needs no DNS in CI.
	_, baseURL, err := normalizeScanBaseURL("http://8.8.8.8/")
	if err != nil {
		t.Fatalf("normalizeScanBaseURL(public) returned error: %v", err)
	}
	if !strings.HasPrefix(baseURL, "http://8.8.8.8") {
		t.Fatalf("unexpected normalized baseURL for public target: %q", baseURL)
	}
}
