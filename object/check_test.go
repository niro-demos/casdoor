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

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

// deleteUserRow removes a user directly, bypassing DeleteUser's dependency on
// the global userEnforcer (wired up by object.InitUserManager, which this
// package-level test does not need for the rest of its setup).
func deleteUserRow(t *testing.T, user *User) {
	t.Helper()
	if _, err := ormer.Engine.ID(core.PK{user.Owner, user.Name}).Delete(&User{}); err != nil {
		t.Logf("cleanup: failed to delete user %s: %v", user.GetId(), err)
	}
}

// TestCheckUserPermissionScopesAppToOwnOrganization reproduces the
// TC-A2059D90 trust assumption inside CheckUserPermission: an
// app-authenticated identity (requestUserId of the form "app/<name>", see
// routers.getUsernameByClientIdSecret) must only be granted permission over
// users that belong to the calling application's own organization, not over
// every tenant's users.
func TestCheckUserPermissionScopesAppToOwnOrganization(t *testing.T) {
	createDatabase = false
	InitConfig()
	InitDb()

	suffix := util.GenerateId()[:8]
	orgAlphaName := "check-test-org-alpha-" + suffix
	orgBetaName := "check-test-org-beta-" + suffix
	appName := "check-test-app-alpha-" + suffix

	orgAlpha := &Organization{Owner: "admin", Name: orgAlphaName, DisplayName: "Alpha"}
	orgBeta := &Organization{Owner: "admin", Name: orgBetaName, DisplayName: "Beta"}
	if ok, err := AddOrganization(orgAlpha); err != nil || !ok {
		t.Fatalf("failed to seed org alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = DeleteOrganization(orgAlpha) })
	if ok, err := AddOrganization(orgBeta); err != nil || !ok {
		t.Fatalf("failed to seed org beta: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = DeleteOrganization(orgBeta) })

	appAlpha := &Application{Owner: "admin", Name: appName, Organization: orgAlphaName, DisplayName: "Alpha App"}
	if ok, err := AddApplication(appAlpha); err != nil || !ok {
		t.Fatalf("failed to seed application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = DeleteApplication(appAlpha) })

	// Every organization needs at least one application for AddUser to
	// accept new users into it.
	appBeta := &Application{Owner: "admin", Name: "check-test-app-beta-" + suffix, Organization: orgBetaName, DisplayName: "Beta App"}
	if ok, err := AddApplication(appBeta); err != nil || !ok {
		t.Fatalf("failed to seed beta application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = DeleteApplication(appBeta) })

	userAlpha := &User{Id: util.GenerateId(), Owner: orgAlphaName, Name: "alice-" + suffix, Password: "123"}
	if ok, err := AddUser(userAlpha, "en"); err != nil || !ok {
		t.Fatalf("failed to seed user alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { deleteUserRow(t, userAlpha) })

	userBeta := &User{Id: util.GenerateId(), Owner: orgBetaName, Name: "bob-" + suffix, Password: "123"}
	if ok, err := AddUser(userBeta, "en"); err != nil || !ok {
		t.Fatalf("failed to seed user beta: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { deleteUserRow(t, userBeta) })

	appIdentity := util.GetId("app", appName)

	// THE VIOLATION: app-alpha's own client credentials must not grant
	// permission over org beta's user.
	hasPermission, _ := CheckUserPermission(appIdentity, userBeta.GetId(), true, "en")
	if hasPermission {
		t.Fatalf("invariant violated: app %q (organization %q) was granted permission over user %q in organization %q", appName, orgAlphaName, userBeta.GetId(), orgBetaName)
	}

	// GREEN CONTROL: app-alpha's own client credentials must still work for
	// its own organization's users.
	hasPermission, err := CheckUserPermission(appIdentity, userAlpha.GetId(), true, "en")
	if !hasPermission {
		t.Fatalf("regression: app %q was denied permission over its own organization %q's user %q: %v", appName, orgAlphaName, userAlpha.GetId(), err)
	}
}
