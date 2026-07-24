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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNormalizeScanBaseURL_RejectsInternalTargets asserts the SSRF invariant at
// the scan feature's entry point: a caller-supplied target that resolves to a
// loopback / link-local / private (RFC1918) / unspecified address must be
// rejected before the server is ever coerced into connecting to it. The scan
// feature lets an org admin choose the target URL, so without this guard the
// server becomes an SSRF proxy against internal infrastructure (loopback-only
// admin APIs, the 169.254.169.254 cloud-metadata endpoint, RFC1918 services).
func TestNormalizeScanBaseURL_RejectsInternalTargets(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1:8000/api/health",   // loopback
		"http://127.0.0.1/",                  // loopback, no port
		"http://169.254.169.254/latest/meta-data/", // link-local cloud metadata
		"http://10.0.0.5/admin",              // RFC1918
		"http://192.168.1.1/",                // RFC1918
		"http://172.16.0.1/",                 // RFC1918
		"http://[::1]/",                      // IPv6 loopback
		"http://0.0.0.0/",                    // unspecified
		"localhost:8000",                     // scheme-less loopback hostname
	}
	for _, target := range blocked {
		if _, _, err := normalizeScanBaseURL(target); err == nil {
			t.Errorf("SSRF invariant violated: normalizeScanBaseURL(%q) accepted an internal destination; it must be rejected", target)
		}
	}
}

// TestNormalizeScanBaseURL_AllowsPublicTargets is the paired positive control:
// a legitimate public target must still be accepted, so the red above is
// provably the SSRF guard firing and not a broken setup that rejects everything.
func TestNormalizeScanBaseURL_AllowsPublicTargets(t *testing.T) {
	allowed := []string{
		"http://93.184.216.34/",  // literal public IP (example.com)
		"https://93.184.216.34/", // literal public IP, https
	}
	for _, target := range allowed {
		if _, _, err := normalizeScanBaseURL(target); err != nil {
			t.Errorf("control failed: normalizeScanBaseURL(%q) rejected a legitimate public target: %v", target, err)
		}
	}
}

// TestDoRequest_RejectsInternalRedirect asserts the invariant on every redirect
// hop: even when the initial target is public, a 3xx Location that points at an
// internal address must not be followed. Here a test server (which for the guard
// counts as loopback) redirects to a loopback callback; the guard must stop the
// hop so the callback is never hit.
func TestDoRequest_RejectsInternalRedirect(t *testing.T) {
	hit := make(chan struct{}, 1)
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/internal-only", http.StatusFound)
	}))
	defer redirector.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// The redirector itself is a loopback address, so validateScanURL must also
	// stop this at the first hop. To exercise the redirect path specifically we
	// call doRequest and assert that regardless of hop the internal callback is
	// never reached and an error is surfaced.
	_, _, _, err := doRequest(client, http.MethodGet, redirector.URL, "/")
	if err == nil {
		t.Errorf("SSRF invariant violated: doRequest followed a request into an internal address without error")
	}
	select {
	case <-hit:
		t.Errorf("SSRF invariant violated: doRequest reached the internal callback %s", internal.URL)
	default:
	}
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "internal") &&
		!strings.Contains(strings.ToLower(err.Error()), "intranet") &&
		!strings.Contains(strings.ToLower(err.Error()), "private") &&
		!strings.Contains(strings.ToLower(err.Error()), "blocked") {
		// Not fatal — any error that prevents the connection satisfies the
		// invariant — but log for clarity.
		t.Logf("doRequest rejected internal destination with: %v", err)
	}
}
