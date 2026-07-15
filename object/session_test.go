// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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
	"encoding/json"
	"strings"
	"testing"
)

// TestGetSessionsApiResponseDoesNotLeakRawSessionId reproduces TC-E849711B:
// controllers/session.go's GetSessions/GetSingleSession serialize
// object.Session verbatim, including the raw, live beego session-store id —
// the exact value carried in the casdoor_session_id auth cookie — to any org
// admin who is authorized only to view session metadata. That raw id is
// then directly replayable as the victim's live login cookie: a full
// account-takeover primitive with no password or MFA needed.
//
// Invariant under test: the data returned to an API caller (what
// controllers/session.go actually hands to c.ResponseOk / json.Marshal) must
// never contain the raw, replayable session-store id verbatim.
//
// This exercises RedactSessionsForApi/RedactSessionForApi, the exact
// transform controllers/session.go's GetSessions/GetSingleSession apply to
// the DB-fetched sessions before responding.
func TestGetSessionsApiResponseDoesNotLeakRawSessionId(t *testing.T) {
	rawBobSessionId := "b8ab74ba6a79b4a62cbf643f840fecc5"
	bobSession := &Session{
		Owner:       "acme",
		Name:        "bob",
		Application: "app-acme",
		SessionId:   []string{"31a2a4728d6c5ac1b7275433da555b12", rawBobSessionId},
	}

	// This is exactly what controllers/session.go's GetSessions handler does
	// with the DB-fetched sessions before calling c.ResponseOk(...).
	apiSessions := RedactSessionsForApi([]*Session{bobSession})

	body, err := json.Marshal(apiSessions)
	if err != nil {
		t.Fatalf("failed to marshal API response: %v", err)
	}

	for _, rawId := range bobSession.SessionId {
		if strings.Contains(string(body), rawId) {
			t.Fatalf("GetSessions API response leaks bob's raw, live, replayable session id %q verbatim: %s", rawId, string(body))
		}
	}

	// Control: the caller must still get one opaque identifier per real
	// session so the admin UI can still show a count / allow revocation —
	// this proves the fix redacts rather than silently dropping data.
	if len(apiSessions) != 1 || len(apiSessions[0].SessionId) != len(bobSession.SessionId) {
		t.Fatalf("expected redacted response to preserve session entry shape, got %+v", apiSessions)
	}

	// Same invariant for the singular GetSingleSession endpoint
	// (controllers/session.go's GetSingleSession -> object.RedactSessionForApi).
	singleBody, err := json.Marshal(RedactSessionForApi(bobSession))
	if err != nil {
		t.Fatalf("failed to marshal single-session API response: %v", err)
	}
	if strings.Contains(string(singleBody), rawBobSessionId) {
		t.Fatalf("GetSingleSession API response leaks bob's raw, live, replayable session id verbatim: %s", string(singleBody))
	}
}

// TestResolveSessionIdRevokesByRedactedIdentifier proves that after
// redaction, the delete-session flow (which now only ever receives the
// opaque identifier the admin UI displays) can still resolve it back to the
// real, raw session id for revocation — so fixing the leak does not break
// the legitimate "delete this session" action.
func TestResolveSessionIdRevokesByRedactedIdentifier(t *testing.T) {
	candidates := []string{"31a2a4728d6c5ac1b7275433da555b12", "b8ab74ba6a79b4a62cbf643f840fecc5"}

	apiIdentifier := HashSessionId(candidates[1])
	if apiIdentifier == candidates[1] {
		t.Fatalf("HashSessionId must not return the raw session id verbatim")
	}

	resolved := ResolveSessionId(candidates, apiIdentifier)
	if resolved != candidates[1] {
		t.Fatalf("ResolveSessionId(%q) = %q, want %q (the real raw id to revoke)", apiIdentifier, resolved, candidates[1])
	}

	// An unknown identifier must not be silently mapped to some real session.
	unknown := ResolveSessionId(candidates, "not-a-real-identifier")
	if unknown != "not-a-real-identifier" {
		t.Fatalf("ResolveSessionId with an unrecognized identifier should return it unchanged, got %q", unknown)
	}
}
