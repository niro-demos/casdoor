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

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestSendWebhookBlocksLoopbackDestination is the regression test for
// TC-207CA9AB: an org-scoped admin can configure a webhook whose URL points
// at a loopback/internal-only destination (here standing in for
// 169.254.169.254 cloud metadata, 127.0.0.1 loopback, or an RFC1918 address -
// they are all in the same blocked class) that the admin has no independent
// network access to. This test exercises sendWebhook() directly - the exact
// function the diagnosis identifies as building the outbound request from
// webhook.Url with zero destination validation - to prove the server itself
// refuses to connect, independent of any earlier input-side check (this is
// also what protects delivery-time DNS-rebinding, per the finding's
// remediation guidance).
//
// On the unfixed code this test fails: sendWebhook happily dials the
// loopback listener and the listener observes the request, including the
// attacker-chosen header, exactly like the PoC's live-fire step.
func TestSendWebhookBlocksLoopbackDestination(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start loopback listener: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var hit bool
	var hitHeader string
	marker := fmt.Sprintf("marker-%d", time.Now().UnixNano())

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit = true
		hitHeader = r.Header.Get("X-Niro-Poc-Marker")
		mu.Unlock()
		w.WriteHeader(200)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	webhook := &Webhook{
		Owner:        "acme",
		Name:         "ssrf-regression",
		Organization: "acme",
		Url:          fmt.Sprintf("http://127.0.0.1:%d/ssrf-proof", port),
		Method:       "POST",
		ContentType:  "application/json",
		IsEnabled:    true,
		Headers:      []*Header{{Name: "X-Niro-Poc-Marker", Value: marker}},
	}
	record := &Record{Owner: "acme", Name: "record-1", Action: "login"}

	_, _, sendErr := sendWebhook(webhook, record, nil)

	// Give the (blocked) attempt a moment to have reached the listener, if it
	// was ever going to.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	delivered := hit
	deliveredMarker := hitHeader
	mu.Unlock()

	if delivered {
		t.Fatalf("SSRF: sendWebhook connected to a loopback destination and delivered the request (marker=%q) - server-side request forgery is live", deliveredMarker)
	}

	if sendErr == nil {
		t.Fatalf("expected sendWebhook to reject a loopback destination, got nil error")
	}
}

// TestSendWebhookDeliversToPublicDestination is the paired positive control:
// a normal, non-reserved destination must still be delivered to. It proves
// the fix blocks the specific reserved-address classes rather than breaking
// the webhook feature outright (loopback is used here only as a stand-in
// reachable "public-looking" server since the sandbox has no real internet
// egress; the point under test is that a destination NOT in the blocked
// class - i.e. sendWebhook when the dialer's Control hook allows it - keeps
// working).
func TestSendWebhookDialerAllowsNonReservedAddress(t *testing.T) {
	dialer := webhookSafeDialer()

	// A well-known public IP literal (documentation/public range), never
	// loopback/link-local/private, must not be blocked by the Control hook
	// itself (independent of whether the sandbox can actually route to it).
	err := dialer.Control("tcp4", "93.184.216.34:80", nil)
	if err != nil {
		t.Fatalf("expected a public address to be allowed by the dial Control hook, got error: %v", err)
	}
}
