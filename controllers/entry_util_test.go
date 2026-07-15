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
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

var entryUtilTestEnvOnce sync.Once

func setupEntryUtilTestEnv(t *testing.T) {
	t.Helper()
	entryUtilTestEnvOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
	})
}

// newOtlpIngestRequest builds a *context.Context for an unauthenticated POST
// to /api/v1/traces the same way beego's router would for a live request,
// without needing a live HTTP server. remoteAddr simulates the real TCP peer
// address (what a load balancer/reverse proxy or the OS would report);
// forgedXFF, if non-empty, simulates a client-supplied X-Forwarded-For
// header - which, unlike RemoteAddr, any caller can set to any value.
func newOtlpIngestRequest(remoteAddr, forgedXFF string) *context.Context {
	req := httptest.NewRequest("POST", "http://localhost:8000/api/v1/traces", nil)
	req.RemoteAddr = remoteAddr
	if forgedXFF != "" {
		req.Header.Set("X-Forwarded-For", forgedXFF)
	}
	rec := httptest.NewRecorder()

	ctx := context.NewContext()
	ctx.Reset(rec, req)
	return ctx
}

// TestResolveOpenClawProviderRejectsForgedForwardedFor is the regression
// test for TC-06541321: the OTLP telemetry-ingest endpoints
// (/api/v1/traces, /api/v1/metrics, /api/v1/logs) authorize the request
// solely by comparing the caller's IP against a Provider's allowlisted
// Host. Invariant: that decision must be based on the real TCP peer
// address, not on a client-supplied X-Forwarded-For header that any
// unauthenticated caller can set to an arbitrary value.
func TestResolveOpenClawProviderRejectsForgedForwardedFor(t *testing.T) {
	setupEntryUtilTestEnv(t)

	const allowlistedIP = "10.13.37.199"
	const attackerIP = "203.0.113.50"

	providerName := fmt.Sprintf("test-openclaw-tc06541321-%d", time.Now().UnixNano())
	provider := &object.Provider{
		Owner:       "admin",
		Name:        providerName,
		DisplayName: "TC-06541321 regression test OpenClaw provider",
		CreatedTime: time.Now().UTC().Format(time.RFC3339),
		Category:    "Log",
		Type:        "Agent",
		SubType:     "OpenClaw",
		State:       "Enabled",
		Host:        allowlistedIP,
	}
	added, err := object.AddProvider(provider)
	if err != nil || !added {
		t.Fatalf("failed to seed OpenClaw provider: added=%v err=%v", added, err)
	}
	t.Cleanup(func() {
		if _, err := object.DeleteProvider(provider); err != nil {
			t.Errorf("failed to clean up test provider: %v", err)
		}
	})

	// Control: the real caller IP (attackerIP) is NOT allowlisted and no
	// X-Forwarded-For header is sent. This must be rejected - it proves the
	// allowlist itself, and this test's setup, are healthy.
	ctx := newOtlpIngestRequest(attackerIP+":54321", "")
	_, status, err := resolveOpenClawProvider(ctx)
	if err == nil || status != 403 {
		t.Fatalf("control failed: expected an unallowlisted real IP with no forged header to be rejected with 403, got status=%d err=%v (environment/setup problem, not the bug under test)", status, err)
	}

	// Red case: identical unauthenticated caller, but now with a forged
	// X-Forwarded-For set to the allowlisted collector IP. A secure
	// implementation must still reject this, since RemoteAddr (the real
	// peer) is still attackerIP - X-Forwarded-For is attacker-controlled.
	ctx = newOtlpIngestRequest(attackerIP+":54321", allowlistedIP)
	_, status, err = resolveOpenClawProvider(ctx)
	if err == nil || status != 403 {
		t.Fatalf("VULNERABLE: forged X-Forwarded-For: %s bypassed the IP allowlist for an attacker whose real address is %s (expected 403, got status=%d err=%v)", allowlistedIP, attackerIP, status, err)
	}

	// Positive control: the legitimate collector, connecting directly from
	// the allowlisted IP with no forged header, must still be accepted -
	// proves the fix doesn't just reject everything.
	ctx = newOtlpIngestRequest(allowlistedIP+":9999", "")
	_, status, err = resolveOpenClawProvider(ctx)
	if err != nil || status != 0 {
		t.Fatalf("legitimate collector request from the allowlisted IP was rejected: status=%d err=%v", status, err)
	}
}
