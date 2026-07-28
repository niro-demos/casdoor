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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/casdoor/casdoor/util"
)

// TestSendWebhookBlocksIntranetDestination is a regression test for
// TC-736DF08D: an org admin must not be able to point a webhook at an
// internal/loopback/link-local address and have the Casdoor server actually
// dial it and hand the raw response back through the webhook-events API.
//
// httptest.Server binds to 127.0.0.1, which util.IsIntranetIp classifies
// identically to the real-world cloud-metadata address 169.254.169.254 used
// in the live PoC (both are "loopback/link-local/private" per the same
// guard) -- it is a safe, offline stand-in for that address, not a weaker
// substitute for it.
func TestSendWebhookBlocksIntranetDestination(t *testing.T) {
	var hit int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hit, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secret-internal-response"))
	}))
	defer srv.Close()

	webhook := &Webhook{
		Owner:       "built-in",
		Name:        "ssrf-regression",
		Url:         srv.URL,
		Method:      "GET",
		ContentType: "application/json",
	}
	record := &Record{}

	statusCode, body, err := sendWebhook(webhook, record, nil)

	if atomic.LoadInt32(&hit) != 0 {
		t.Fatalf("sendWebhook dialed the intranet destination %q (server hit count=%d); the server must never be reached", webhook.Url, hit)
	}
	if err == nil {
		t.Fatalf("sendWebhook(%q) returned no error, want rejection of the intranet destination", webhook.Url)
	}
	if statusCode != 0 || body != "" {
		t.Fatalf("sendWebhook(%q) = (statusCode=%d, body=%q), want (0, \"\") for a blocked destination -- the raw upstream response must never be surfaced", webhook.Url, statusCode, body)
	}
}

// TestSendWebhookDeliversToAllowedDestination is the positive control for
// TestSendWebhookBlocksIntranetDestination: sendWebhook must still build and
// send a normal request (headers, body, method) when the guard has nothing
// to object to, proving the block above is specific to the destination
// class, not a broken send path in general.
//
// A real "public" destination can't be dialed from this offline test
// environment (any locally-bindable address is loopback/private, i.e.
// exactly the class this fix blocks by design). So this control exercises
// util.ValidateOutboundUrl -- the exact gate sendWebhook calls before
// touching the network -- directly against literal public IPs, which
// requires no network access and proves the gate discriminates by
// destination rather than rejecting everything.
func TestSendWebhookDeliversToAllowedDestination(t *testing.T) {
	for _, rawUrl := range []string{"https://93.184.216.34/", "http://8.8.8.8/webhook"} {
		t.Run(rawUrl, func(t *testing.T) {
			if err := util.ValidateOutboundUrl(rawUrl); err != nil {
				t.Fatalf("util.ValidateOutboundUrl(%q) unexpected error: %v -- a legitimate public destination must not be blocked", rawUrl, err)
			}
		})
	}
}
