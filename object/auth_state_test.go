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

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/session"
)

func TestRevokeUserAuthenticationStateExpiresTokensAndSessions(t *testing.T) {
	setupAuthStateTestDb(t)

	targetToken := &Token{
		Owner:        "admin",
		Name:         "target-token",
		Application:  "app-built-in",
		Organization: "org-a",
		User:         "alice",
		AccessToken:  "target-access-token",
		ExpiresIn:    3600,
	}
	otherToken := &Token{
		Owner:        "admin",
		Name:         "other-token",
		Application:  "app-built-in",
		Organization: "org-a",
		User:         "bob",
		AccessToken:  "other-access-token",
		ExpiresIn:    3600,
	}

	if _, err := AddToken(targetToken); err != nil {
		t.Fatalf("AddToken(target) error = %v", err)
	}
	if _, err := AddToken(otherToken); err != nil {
		t.Fatalf("AddToken(other) error = %v", err)
	}

	if _, err := AddSession(&Session{Owner: "org-a", Name: "alice", Application: "app-built-in", SessionId: []string{"stale-session-1", "stale-session-2"}}); err != nil {
		t.Fatalf("AddSession(target) error = %v", err)
	}
	if _, err := AddSession(&Session{Owner: "org-a", Name: "bob", Application: "app-built-in", SessionId: []string{"other-session"}}); err != nil {
		t.Fatalf("AddSession(other) error = %v", err)
	}

	if err := RevokeUserAuthenticationState("org-a", "alice"); err != nil {
		t.Fatalf("RevokeUserAuthenticationState() error = %v", err)
	}

	activeTargetTokens, err := GetActiveTokensByUser("org-a", "alice")
	if err != nil {
		t.Fatalf("GetActiveTokensByUser(target) error = %v", err)
	}
	if len(activeTargetTokens) != 0 {
		t.Fatalf("target active tokens = %d, want 0", len(activeTargetTokens))
	}

	targetSessions, err := GetUserSessions("org-a", "alice")
	if err != nil {
		t.Fatalf("GetUserSessions(target) error = %v", err)
	}
	if len(targetSessions) != 0 {
		t.Fatalf("target sessions = %d, want 0", len(targetSessions))
	}

	activeOtherTokens, err := GetActiveTokensByUser("org-a", "bob")
	if err != nil {
		t.Fatalf("GetActiveTokensByUser(other) error = %v", err)
	}
	if len(activeOtherTokens) != 1 {
		t.Fatalf("other active tokens = %d, want 1", len(activeOtherTokens))
	}

	otherSessions, err := GetUserSessions("org-a", "bob")
	if err != nil {
		t.Fatalf("GetUserSessions(other) error = %v", err)
	}
	if len(otherSessions) != 1 || len(otherSessions[0].SessionId) != 1 || otherSessions[0].SessionId[0] != "other-session" {
		t.Fatalf("other sessions = %#v, want one unchanged session", otherSessions)
	}
}

func setupAuthStateTestDb(t *testing.T) {
	t.Helper()

	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", t.TempDir()+"/casdoor-auth-state-test.db")
	t.Setenv("dbName", "")

	oldCreateDatabase := createDatabase
	createDatabase = false
	InitAdapter()
	CreateTables()
	t.Cleanup(func() {
		createDatabase = oldCreateDatabase
		if ormer != nil && ormer.Engine != nil {
			_ = ormer.Engine.Close()
		}
		ormer = nil
	})

	var err error
	web.GlobalSessions, err = session.NewManager("memory", session.NewManagerConfig())
	if err != nil {
		t.Fatalf("session.NewManager() error = %v", err)
	}
}
