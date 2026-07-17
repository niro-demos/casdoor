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
	"encoding/json"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/object"
)

// TestRedactSessionsStripsReplayableSessionId asserts the invariant behind
// TC-BDB2FFB9: organization admins and the global admin must not be able to
// obtain other users' live login-session identifiers in a form that can be
// replayed as their authentication cookie. GetSessions()/GetSingleSession()
// used to hand the literal object.Session (with its raw, replayable
// SessionId values) straight to c.ResponseOk, so the JSON response leaked
// the exact bytes that the casdoor_session_id auth cookie accepts.
//
// This test exercises the same function the controller calls before
// serializing its response (redactSessions) and asserts that the resulting
// JSON never contains a literal, live session id - only a count.
func TestRedactSessionsStripsReplayableSessionId(t *testing.T) {
	const leakedSessionId = "f58d03ef65c4e404d3a1d3a94b83a268"

	sessions := []*object.Session{
		{
			Owner:       "acme",
			Name:        "bob",
			Application: "app-acme",
			CreatedTime: "2026-07-17T00:00:00Z",
			SessionId:   []string{leakedSessionId},
		},
		{
			Owner:       "acme",
			Name:        "acme-admin",
			Application: "app-acme",
			CreatedTime: "2026-07-17T00:00:00Z",
			SessionId:   []string{"unrelated-admin-session-id"},
		},
	}

	redacted := redactSessions(sessions)

	data, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("failed to marshal redacted sessions: %v", err)
	}
	body := string(data)

	if strings.Contains(body, leakedSessionId) {
		t.Fatalf("VULNERABLE: redacted API response still contains the literal, replayable session id %q - this value is byte-for-byte what the casdoor_session_id auth cookie accepts, so leaking it allows silent account takeover. Response body: %s", leakedSessionId, body)
	}
	if strings.Contains(body, "unrelated-admin-session-id") {
		t.Fatalf("VULNERABLE: redacted API response still contains a literal session id. Response body: %s", body)
	}

	// Control: the count must still be reported so the legitimate
	// "how many active sessions does this user have" admin UX keeps working.
	if !strings.Contains(body, `"sessionCount":1`) {
		t.Fatalf("expected redacted response to report sessionCount, got: %s", body)
	}

	// Sanity: the input sessions passed to redactSessions must not have been
	// silently no-op'd - the original SessionId slice on the redacted struct
	// must be gone (nil/empty), not merely left in place while some other
	// field carries the leak.
	for _, s := range redacted {
		if len(s.SessionId) != 0 {
			t.Fatalf("expected SessionId to be cleared after redaction, got %v", s.SessionId)
		}
	}
}
