// Copyright 2024 The Casdoor Authors. All Rights Reserved.
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
	"strings"
	"testing"
)

// setupSessionTestDB points the package-level ormer at a private, in-memory
// sqlite database and creates just the sessions table, so these tests don't
// need a configured MySQL/Postgres instance or conf/app.conf. The previous
// ormer (if any) is restored when the test finishes so this doesn't leak
// into other tests in the package. Each test gets a database uniquely named
// after itself: Go's database/sql pool can open several connections against
// the same DSN, so the DSN uses sqlite's shared-cache mode to keep those
// connections talking to the same in-memory database within one test,
// while distinct tests (and any parallel run of this test) don't see each
// other's rows.
func setupSessionTestDB(t *testing.T) {
	t.Helper()

	prevOrmer := ormer
	t.Cleanup(func() {
		ormer = prevOrmer
	})

	dbName := "session_test_" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	a, err := NewAdapter("sqlite", "file:"+dbName+"?mode=memory&cache=shared", dbName)
	if err != nil {
		t.Fatalf("failed to create in-memory test adapter: %v", err)
	}
	ormer = a

	if err := ormer.Engine.Sync2(new(Session)); err != nil {
		t.Fatalf("failed to sync sessions table: %v", err)
	}
}

// TestGetSessionsAndGetSingleSessionNeverExposeRawReplayableToken is the
// regression test for TC-72FA2D0B: GET /api/get-sessions and
// GET /api/get-session must never hand an admin the raw casdoor_session_id
// value of another user's session, because that raw value is itself a
// live, replayable authentication credential (see object/session.go's
// maskSessionId / GetMaskedSession, and controllers/session.go's
// GetSessions / GetSingleSession, which now route every session through
// them before it reaches the HTTP response).
func TestGetSessionsAndGetSingleSessionNeverExposeRawReplayableToken(t *testing.T) {
	setupSessionTestDB(t)

	aliceRawToken := "5022c8b715c8c2e7f7f2d093051cb613"
	bobRawToken := "8c3190c99c55ac575c4ae2b862187731"

	if _, err := AddSession(&Session{Owner: "acme", Name: "alice", Application: "app-acme", SessionId: []string{aliceRawToken}}); err != nil {
		t.Fatalf("failed to seed alice's session: %v", err)
	}
	if _, err := AddSession(&Session{Owner: "acme", Name: "bob", Application: "app-acme", SessionId: []string{bobRawToken}}); err != nil {
		t.Fatalf("failed to seed bob's session: %v", err)
	}

	// Positive control: the raw token really is what's persisted internally
	// (proves this is a genuine fixture, not a broken/empty environment).
	rawSingle, err := GetSingleSession("acme/alice/app-acme")
	if err != nil {
		t.Fatalf("GetSingleSession: %v", err)
	}
	if rawSingle == nil || len(rawSingle.SessionId) != 1 || rawSingle.SessionId[0] != aliceRawToken {
		t.Fatalf("control failed: expected internal storage to hold alice's raw token, got %+v", rawSingle)
	}

	// --- The invariant under test: the API-facing listing must not expose it.
	maskedList, err := GetMaskedSessions(GetSessions("acme"))
	if err != nil {
		t.Fatalf("GetMaskedSessions(GetSessions): %v", err)
	}
	if len(maskedList) != 2 {
		t.Fatalf("expected 2 sessions in org acme, got %d", len(maskedList))
	}

	for _, s := range maskedList {
		for _, id := range s.SessionId {
			if id == aliceRawToken {
				t.Fatalf("VULNERABLE: get-sessions response for owner=acme contains alice's raw, replayable session token verbatim: %q", id)
			}
			if id == bobRawToken {
				t.Fatalf("VULNERABLE: get-sessions response for owner=acme contains bob's raw, replayable session token verbatim: %q", id)
			}
		}
	}

	// The single-session endpoint (GET /api/get-session) must be equally redacted.
	maskedSingle, err := GetMaskedSession(GetSingleSession("acme/alice/app-acme"))
	if err != nil {
		t.Fatalf("GetMaskedSession(GetSingleSession): %v", err)
	}
	if maskedSingle == nil || len(maskedSingle.SessionId) != 1 {
		t.Fatalf("expected exactly one masked session id, got %+v", maskedSingle)
	}
	if maskedSingle.SessionId[0] == aliceRawToken {
		t.Fatalf("VULNERABLE: get-session response for alice contains her raw, replayable session token verbatim: %q", maskedSingle.SessionId[0])
	}
	if maskedSingle.SessionId[0] != maskSessionId(aliceRawToken) {
		t.Fatalf("expected the masked display id to be the deterministic hash of the raw token, got %q", maskedSingle.SessionId[0])
	}
}

// TestSessionIdMatches covers the matcher that lets legitimate callers
// (a caller's own current, raw session id from CruSession.SessionID, or an
// admin who only ever saw a masked id from GetSessions/GetSingleSession)
// still identify a session for revocation/duplication checks, while a
// value that is neither the real token nor its derived mask never matches.
func TestSessionIdMatches(t *testing.T) {
	rawToken := "cc6f40f651924d20d1cf6e9201b25efc"
	masked := maskSessionId(rawToken)

	if masked == rawToken {
		t.Fatalf("masked identifier must differ from the raw token, got the same value %q", masked)
	}
	if len(masked) != sessionIdDisplayLength {
		t.Fatalf("expected masked id of length %d, got %q (len %d)", sessionIdDisplayLength, masked, len(masked))
	}

	if !SessionIdMatches(rawToken, rawToken) {
		t.Fatalf("SessionIdMatches must accept the raw token matching itself")
	}
	if !SessionIdMatches(rawToken, masked) {
		t.Fatalf("SessionIdMatches must accept the token's own masked display id")
	}
	if SessionIdMatches(rawToken, "totally-unrelated-value") {
		t.Fatalf("SessionIdMatches must reject an unrelated candidate")
	}
	if SessionIdMatches(rawToken, "") {
		t.Fatalf("SessionIdMatches must reject an empty candidate")
	}
}

// TestMaskedSessionIdFromOneUserDoesNotMatchAnotherUsersRawToken guards
// against the matcher accidentally letting an admin who only holds one
// user's masked display id use it to identify (and thus revoke/replay-check)
// a different user's raw session token.
func TestMaskedSessionIdFromOneUserDoesNotMatchAnotherUsersRawToken(t *testing.T) {
	aliceRaw := "5022c8b715c8c2e7f7f2d093051cb613"
	bobRaw := "8c3190c99c55ac575c4ae2b862187731"

	aliceMasked := maskSessionId(aliceRaw)

	if SessionIdMatches(bobRaw, aliceMasked) {
		t.Fatalf("alice's masked session id must not match bob's raw session token")
	}
}

// TestDeleteSessionIdAcceptsRawOrMaskedIdentifier proves the fix doesn't
// regress the admin "revoke one session" feature: the admin UI only ever
// receives masked ids from GetSessions/GetSingleSession, so DeleteSessionId
// must resolve a masked id back to the real stored token to revoke it,
// while still supporting server-derived callers (e.g. self-logout) that
// pass the raw token directly.
func TestDeleteSessionIdAcceptsRawOrMaskedIdentifier(t *testing.T) {
	setupSessionTestDB(t)

	tokA := "tokenA-11111111111111111111111111111111"
	tokB := "tokenB-22222222222222222222222222222222"
	id := "acme/alice/app-acme"

	if _, err := AddSession(&Session{Owner: "acme", Name: "alice", Application: "app-acme", SessionId: []string{tokA, tokB}}); err != nil {
		t.Fatalf("failed to seed alice's session: %v", err)
	}

	// An admin revoking via the masked id shown by the (now-fixed) listing
	// endpoint must still be able to remove exactly that token.
	maskedTokA := maskSessionId(tokA)
	ok, err := DeleteSessionId(id, maskedTokA)
	if err != nil {
		t.Fatalf("DeleteSessionId(masked): %v", err)
	}
	if !ok {
		t.Fatalf("DeleteSessionId(masked) should have revoked tokA via its masked identifier")
	}

	remaining, err := GetSingleSession(id)
	if err != nil {
		t.Fatalf("GetSingleSession after delete: %v", err)
	}
	if remaining == nil || len(remaining.SessionId) != 1 || remaining.SessionId[0] != tokB {
		t.Fatalf("expected only tokB to remain after revoking tokA, got %+v", remaining)
	}

	// A value that is neither a real token nor a valid mask must not delete anything.
	ok, err = DeleteSessionId(id, "not-a-real-or-masked-value")
	if err != nil {
		t.Fatalf("DeleteSessionId(bogus): %v", err)
	}
	if ok {
		t.Fatalf("DeleteSessionId must not report success for an unrecognized identifier")
	}
	remaining, err = GetSingleSession(id)
	if err != nil {
		t.Fatalf("GetSingleSession after no-op delete: %v", err)
	}
	if remaining == nil || len(remaining.SessionId) != 1 || remaining.SessionId[0] != tokB {
		t.Fatalf("bogus delete must not have modified the session, got %+v", remaining)
	}

	// Server-derived callers that already hold the raw token (e.g. self-logout,
	// which reads it from CruSession.SessionID, never from a listing response)
	// must keep working unmasked.
	ok, err = DeleteSessionId(id, tokB)
	if err != nil {
		t.Fatalf("DeleteSessionId(raw): %v", err)
	}
	if !ok {
		t.Fatalf("DeleteSessionId(raw) should have revoked tokB via its raw value")
	}
}
