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
	"testing"
)

// TestSendWebhookRejectsInternalDestination covers TC-EB34E6CF: an org-scoped
// admin must not be able to make the server deliver a webhook to a
// loopback/link-local/private destination and read the internal response back.
// sendWebhook is the single delivery sink, so the egress guard must fire here
// before any outbound request is issued. This runs without a DB connection.
func TestSendWebhookRejectsInternalDestination(t *testing.T) {
	// Loopback targets: on the unfixed code these connect/refuse fast, so the
	// test proves the guard is wired into the sink without depending on a slow
	// dial to an unroutable private address. The exhaustive range matrix
	// (RFC1918, link-local, metadata) is asserted instantly in
	// util.TestIsDisallowedOutboundIP / util.TestCheckOutboundHost.
	internalURLs := []string{
		"http://127.0.0.1:8000/api/get-version-info",
		"http://localhost:8000/api/get-version-info",
		"http://[::1]:8000/api/get-version-info",
	}

	record := &Record{Organization: "org-alpha", Action: "login"}

	for _, url := range internalURLs {
		t.Run("reject/"+url, func(t *testing.T) {
			webhook := &Webhook{
				Owner:        "org-alpha",
				Name:         "ssrf-probe",
				Organization: "org-alpha",
				Url:          url,
				Method:       "GET",
				ContentType:  "application/json",
			}
			statusCode, response, err := sendWebhook(webhook, record, nil)
			if err == nil {
				t.Fatalf("sendWebhook to internal URL %q returned nil error (statusCode=%d, response=%q); expected the destination to be rejected before the outbound request", url, statusCode, response)
			}
		})
	}
}
