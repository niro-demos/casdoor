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
	"strings"
	"testing"

	"github.com/casdoor/casdoor/util"
)

// TestCheckUserPasswordDoesNotDiscloseUsernameExistence is the regression
// test for TC-435A4216: "Login endpoint discloses username existence via
// distinct error messages".
//
// Invariant under test: CheckUserPassword (the function backing the
// password-based /api/login flow in controllers.Login) must not reveal,
// via its error message, whether a submitted username exists in an
// organization. A failed sign-in must not use "doesn't exist" style
// wording for a username that was never created.
//
// The test provisions its own throwaway organization, application and user
// (uniquely named per run) instead of relying on the shared "built-in"
// organization, since object-package tests in this project run against a
// live, shared database rather than an isolated per-test one.
func TestCheckUserPasswordDoesNotDiscloseUsernameExistence(t *testing.T) {
	InitConfig()
	InitDb()
	InitUserManager()

	suffix := util.GenerateId()
	orgName := "niroverify-org-tc435a4216-" + suffix
	appName := "niroverify-app-tc435a4216-" + suffix
	ownedUser := "niroverify-user-tc435a4216-" + suffix
	ghostUser := "niroverify-ghost-tc435a4216-" + suffix
	const ownedPass = "NiroVerify-Pw1!"

	organization := &Organization{
		Owner:        "admin",
		Name:         orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  orgName,
		PasswordType: "plain",
	}
	if ok, err := AddOrganization(organization); err != nil || !ok {
		t.Fatalf("failed to create throwaway organization %s: ok=%v err=%v", orgName, ok, err)
	}
	defer func() {
		_, _ = DeleteOrganization(organization)
	}()

	application := &Application{
		Owner:          "admin",
		Name:           appName,
		CreatedTime:    util.GetCurrentTime(),
		DisplayName:    appName,
		Organization:   orgName,
		EnablePassword: true,
		SigninMethods: []*SigninMethod{
			{Name: "Password", DisplayName: "Password", Rule: "All"},
		},
	}
	if ok, err := AddApplication(application); err != nil || !ok {
		t.Fatalf("failed to create throwaway application %s: ok=%v err=%v", appName, ok, err)
	}
	defer func() {
		_, _ = DeleteApplication(application)
	}()

	user := &User{
		Owner:       orgName,
		Name:        ownedUser,
		CreatedTime: util.GetCurrentTime(),
		Id:          util.GenerateId(),
		Type:        "normal-user",
		Password:    ownedPass,
		DisplayName: ownedUser,
	}
	if ok, err := AddUser(user, "en"); err != nil || !ok {
		t.Fatalf("failed to create owned test user %s/%s: ok=%v err=%v", orgName, ownedUser, ok, err)
	}
	defer func() {
		_, _ = DeleteUser(user)
	}()

	// Positive control: the correct password for the owned, existing user
	// must succeed. If this fails, the environment itself is broken and a
	// red result below would be meaningless.
	if _, err := CheckUserPassword(orgName, ownedUser, ownedPass, "en"); err != nil {
		t.Fatalf("positive control failed: correct-password login for %s/%s errored: %v — environment is unhealthy, cannot trust a red result", orgName, ownedUser, err)
	}

	// Negative case A: existing user, wrong password.
	_, wrongPassErr := CheckUserPassword(orgName, ownedUser, "definitely-wrong-pw-999", "en")
	if wrongPassErr == nil {
		t.Fatalf("wrong password unexpectedly succeeded for %s/%s — cannot evaluate invariant", orgName, ownedUser)
	}

	// Negative case B: a username that was never created.
	_, ghostErr := CheckUserPassword(orgName, ghostUser, "irrelevant-pw", "en")
	if ghostErr == nil {
		t.Fatalf("login for a never-created username %s/%s unexpectedly succeeded", orgName, ghostUser)
	}

	t.Logf("existing-user wrong-password message: %q", wrongPassErr.Error())
	t.Logf("nonexistent-user message:              %q", ghostErr.Error())

	// Invariant: the non-existent-username error must not reveal account
	// existence via a distinct "doesn't exist" style message.
	ghostMsg := strings.ToLower(ghostErr.Error())
	if strings.Contains(ghostMsg, "doesn't exist") || strings.Contains(ghostMsg, "does not exist") {
		t.Fatalf(
			"login endpoint discloses username existence: nonexistent-user error (%q) is distinguishable from wrong-password error (%q) for an existing account",
			ghostErr.Error(), wrongPassErr.Error(),
		)
	}
}
