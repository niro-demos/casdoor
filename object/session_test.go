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
	"reflect"
	"testing"
)

// TestGetMaskedSession asserts the invariant behind TC-F34A1D4D: the raw
// SessionId values (the literal beego session-store key -- the exact value
// issued as the casdoor_session_id cookie, and directly replayable as that
// cookie to fully authenticate as the session's owner without a password)
// must never reach a caller who is neither the session's own owner nor a
// global admin. The owner and a global admin still get the real value back,
// so self-service and legitimate admin session inspection keep working.
func TestGetMaskedSession(t *testing.T) {
	rawSession := func() *Session {
		return &Session{
			Owner:       "niro-test",
			Name:        "alice",
			Application: "app-niro-test",
			CreatedTime: "2026-07-28T06:59:11Z",
			SessionId:   []string{"19fb4c6a35d06aac0f70887cd3e58dc8"},
		}
	}

	tests := []struct {
		name                 string
		isOwnerOrGlobalAdmin bool
		want                 *Session
	}{
		{
			name:                 "non-owner, non-global-admin (e.g. org admin reading another user's session) must have the raw session id redacted",
			isOwnerOrGlobalAdmin: false,
			want: &Session{
				Owner:       "niro-test",
				Name:        "alice",
				Application: "app-niro-test",
				CreatedTime: "2026-07-28T06:59:11Z",
				SessionId:   []string{"***"},
			},
		},
		{
			name:                 "owner or global admin must still receive the real, usable session id",
			isOwnerOrGlobalAdmin: true,
			want:                 rawSession(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMaskedSession(rawSession(), tt.isOwnerOrGlobalAdmin)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetMaskedSession() = %#v, want %#v", got, tt.want)
			}
			if !tt.isOwnerOrGlobalAdmin {
				for _, sid := range got.SessionId {
					if sid == "19fb4c6a35d06aac0f70887cd3e58dc8" {
						t.Fatal("GetMaskedSession() leaked the raw, replayable session id to a non-owner, non-global-admin caller")
					}
				}
			}
		})
	}
}

// TestGetMaskedSessions asserts that listing endpoints (GetSessions /
// GetPaginationSessions) never return raw session ids, mirroring the
// GetMaskedTokens "lists always mask" policy: an org admin listing an
// entire org's sessions must not be able to harvest another user's live,
// replayable session cookie from the list response, regardless of the
// admin's own privilege level.
func TestGetMaskedSessions(t *testing.T) {
	sessions := []*Session{
		{Owner: "niro-test", Name: "alice", Application: "app-niro-test", SessionId: []string{"alice-session-id"}},
		{Owner: "niro-test", Name: "org-admin", Application: "app-niro-test", SessionId: []string{"org-admin-session-id-1", "org-admin-session-id-2"}},
	}
	want := []*Session{
		{Owner: "niro-test", Name: "alice", Application: "app-niro-test", SessionId: []string{"***"}},
		{Owner: "niro-test", Name: "org-admin", Application: "app-niro-test", SessionId: []string{"***", "***"}},
	}

	got := GetMaskedSessions(sessions)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetMaskedSessions() = %#v, want %#v", got, want)
	}
}
