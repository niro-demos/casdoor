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

//go:build !skipCi

package object

import (
	"testing"

	"github.com/xorm-io/core"
)

// deleteUserRow removes a user row directly, bypassing DeleteUser()'s
// userEnforcer/session/third-party-link side effects, which require the
// full application boot sequence (InitDb + InitUserManager) that this
// package-level test does not run.
func deleteUserRow(owner, name string) {
	_, _ = ormer.Engine.ID(core.PK{owner, name}).Delete(&User{})
}

// TestCheckUserPasswordCorrectPasswordSurvivesUnauthenticatedLockout is the
// regression test for TC-2CEB55F9: an unauthenticated caller who does not
// know a user's password must not be able to lock that user out of their
// own account by submitting a few failed login attempts.
//
// Before the fix, checkSigninErrorTimes() ran ahead of password
// verification in CheckPassword(), so once an attacker (who never supplied
// the correct password) drove the failed-attempt counter to the limit, the
// very next login attempt was rejected with the "too many times" lockout
// error even when it carried the account's correct password.
func TestCheckUserPasswordCorrectPasswordSurvivesUnauthenticatedLockout(t *testing.T) {
	InitConfig()

	orgName := "niro-test-lockout-org"
	appName := "niro-test-lockout-app"
	victimName := "niro-test-lockout-victim"
	controlName := "niro-test-lockout-control"
	victimPassword := "NiroLockoutVictim-Pw1!"
	controlPassword := "NiroLockoutControl-Pw1!"

	cleanup := func() {
		deleteUserRow(orgName, victimName)
		deleteUserRow(orgName, controlName)
		_, _ = DeleteApplication(&Application{Owner: "admin", Name: appName})
		_, _ = DeleteOrganization(&Organization{Owner: "admin", Name: orgName})
	}
	cleanup()
	defer cleanup()

	// --- setup: a dedicated org + application + two throwaway users, so the
	// test never touches shared fixtures and always starts from a clean
	// signin-error counter. ---
	if _, err := AddOrganization(&Organization{Owner: "admin", Name: orgName, DisplayName: orgName, PasswordType: "plain"}); err != nil {
		t.Fatalf("setup: failed to create organization: %v", err)
	}
	if _, err := AddApplication(&Application{Owner: "admin", Name: appName, DisplayName: appName, Organization: orgName, EnablePassword: true}); err != nil {
		t.Fatalf("setup: failed to create application: %v", err)
	}
	if _, err := AddUser(&User{Owner: orgName, Name: victimName, Type: "normal-user", Password: victimPassword, DisplayName: victimName}, "en"); err != nil {
		t.Fatalf("setup: failed to create victim user: %v", err)
	}
	if _, err := AddUser(&User{Owner: orgName, Name: controlName, Type: "normal-user", Password: controlPassword, DisplayName: controlName}, "en"); err != nil {
		t.Fatalf("setup: failed to create control user: %v", err)
	}

	// --- positive control #1: the victim can log in normally before any attack. ---
	if _, err := CheckUserPassword(orgName, victimName, victimPassword, "en", false, false, false); err != nil {
		t.Fatalf("baseline: victim login with correct password should succeed before any attack, got error: %v", err)
	}

	// --- attack: 5 unauthenticated wrong-password attempts against the victim,
	// mirroring the PoC (DefaultFailedSigninLimit == 5). ---
	for i := 1; i <= DefaultFailedSigninLimit; i++ {
		_, err := CheckUserPassword(orgName, victimName, "wrong-password-guess", "en", false, false, false)
		if err == nil {
			t.Fatalf("attack: wrong-password attempt %d/%d unexpectedly succeeded", i, DefaultFailedSigninLimit)
		}
	}

	// --- the invariant under test: the victim's CORRECT password, submitted
	// immediately after the attack, must still be accepted -- an
	// unauthenticated attacker who never knew the password must not be able
	// to deny the real owner's login. ---
	_, err := CheckUserPassword(orgName, victimName, victimPassword, "en", false, false, false)
	if err != nil {
		if signinErr, ok := err.(*SigninError); ok && signinErr.Reason == SigninReasonAccountFrozen {
			t.Fatalf("VIOLATION: victim's correct password was rejected by the account-frozen lockout after 5 unauthenticated wrong-password guesses: %v", err)
		}
		t.Fatalf("victim's correct password should have been accepted after the attack, got error: %v", err)
	}

	// --- the lockout must still throttle further WRONG-password attempts:
	// the fix must not remove brute-force protection, only stop it from
	// blocking the correct credential. Drive the counter back up and confirm
	// a 6th wrong guess is still rejected as account-frozen. ---
	for i := 1; i <= DefaultFailedSigninLimit; i++ {
		_, err := CheckUserPassword(orgName, victimName, "wrong-password-guess-again", "en", false, false, false)
		if err == nil {
			t.Fatalf("second attack: wrong-password attempt %d/%d unexpectedly succeeded", i, DefaultFailedSigninLimit)
		}
	}
	_, err = CheckUserPassword(orgName, victimName, "wrong-password-guess-again", "en", false, false, false)
	if err == nil {
		t.Fatalf("expected a 6th consecutive wrong-password attempt to still be throttled by the lockout")
	}
	signinErr, ok := err.(*SigninError)
	if !ok || signinErr.Reason != SigninReasonAccountFrozen {
		t.Fatalf("expected the 6th consecutive wrong-password attempt to be rejected as account-frozen, got: %v", err)
	}

	// --- positive control #2: an unrelated account is unaffected, proving
	// the failure (or fix) is specific to the targeted account. ---
	if _, err := CheckUserPassword(orgName, controlName, controlPassword, "en", false, false, false); err != nil {
		t.Fatalf("control: unrelated account should be unaffected by the attack on the victim, got error: %v", err)
	}
}
