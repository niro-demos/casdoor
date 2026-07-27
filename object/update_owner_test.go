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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateInvitationRejectsOwnerChange(t *testing.T) {
	initSqliteTestConfig(t)

	name := "test-update-invitation-owner-" + time.Now().Format("20060102150405")
	invitation := &Invitation{
		Owner:       "built-in",
		Name:        name,
		DisplayName: "same-owner control",
		Code:        "INV" + strings.ReplaceAll(name, "-", ""),
		DefaultCode: "INV" + strings.ReplaceAll(name, "-", ""),
		Quota:       1,
		Application: "All",
		State:       "Active",
	}
	defer DeleteInvitation(&Invitation{Owner: "built-in", Name: name})
	defer DeleteInvitation(&Invitation{Owner: "admin", Name: name})

	if ok, err := AddInvitation(invitation, "en"); err != nil || !ok {
		t.Fatalf("AddInvitation() ok=%v, err=%v", ok, err)
	}

	invitation.DisplayName = "same-owner update"
	if ok, err := UpdateInvitation(invitation.GetId(), invitation, false, "en"); err != nil || !ok {
		t.Fatalf("same-owner UpdateInvitation() ok=%v, err=%v", ok, err)
	}

	moved := *invitation
	moved.Owner = "admin"
	if ok, err := UpdateInvitation(invitation.GetId(), &moved, false, "en"); err == nil || ok {
		t.Fatalf("cross-owner UpdateInvitation() ok=%v, err=%v, want authorization error", ok, err)
	}

	original, err := GetInvitation(invitation.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if original == nil || original.Owner != "built-in" || original.Name != name {
		t.Fatalf("original invitation moved or disappeared: %+v", original)
	}

	crossOwner, err := GetInvitation("admin/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if crossOwner != nil {
		t.Fatalf("cross-owner invitation was created: %+v", crossOwner)
	}
}

func TestUpdatePermissionRejectsOwnerChange(t *testing.T) {
	initSqliteTestConfig(t)

	name := "test-update-permission-owner-" + time.Now().Format("20060102150405")
	permission := &Permission{
		Owner:       "built-in",
		Name:        name,
		DisplayName: "same-owner control",
		Users:       []string{},
		Groups:      []string{},
		Roles:       []string{},
		Domains:     []string{},
		Resources:   []string{},
		Actions:     []string{},
		Effect:      "Allow",
		IsEnabled:   true,
		State:       "Approved",
	}
	defer DeletePermission(&Permission{Owner: "built-in", Name: name})
	defer DeletePermission(&Permission{Owner: "admin", Name: name})

	if ok, err := AddPermission(permission); err != nil || !ok {
		t.Fatalf("AddPermission() ok=%v, err=%v", ok, err)
	}

	permission.DisplayName = "same-owner update"
	if ok, err := UpdatePermission(permission.GetId(), permission, false, "en"); err != nil || !ok {
		t.Fatalf("same-owner UpdatePermission() ok=%v, err=%v", ok, err)
	}

	moved := *permission
	moved.Owner = "admin"
	if ok, err := UpdatePermission(permission.GetId(), &moved, false, "en"); err == nil || ok {
		t.Fatalf("cross-owner UpdatePermission() ok=%v, err=%v, want authorization error", ok, err)
	}

	original, err := GetPermission(permission.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if original == nil || original.Owner != "built-in" || original.Name != name {
		t.Fatalf("original permission moved or disappeared: %+v", original)
	}

	crossOwner, err := GetPermission("admin/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if crossOwner != nil {
		t.Fatalf("cross-owner permission was created: %+v", crossOwner)
	}
}

func initSqliteTestConfig(t *testing.T) {
	t.Helper()

	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", filepath.Join(t.TempDir(), "casdoor-test.db"))
	t.Setenv("dbName", "")
	createDatabase = false
	InitConfig()
}
