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
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/xorm-io/xorm/names"
)

// setUpIsolatedTestOrmer points the package-level `ormer` at a throwaway
// sqlite database for the duration of the calling test, and restores the
// previous ormer afterwards. This keeps the test hermetic (no dependency on
// a live, pre-seeded MySQL instance) without disturbing any other test that
// relies on the real configured database.
func setUpIsolatedTestOrmer(t *testing.T) {
	t.Helper()

	previous := ormer

	dbFile := filepath.Join(t.TempDir(), "mfa_signin_lockout_test.db")
	dsn := fmt.Sprintf("file:%s?cache=shared&_pragma=busy_timeout(5000)", dbFile)

	testOrmer, err := NewAdapter("sqlite3", dsn, "")
	if err != nil {
		t.Fatalf("failed to create isolated test database: %v", err)
	}
	testOrmer.Engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	testOrmer.createTable()

	ormer = testOrmer
	t.Cleanup(func() {
		ormer = previous
	})
}

// generateTotpCode computes a valid TOTP passcode for secret at time t, using
// the same parameters as TotpMfa.Verify (object/mfa_totp.go): 30s period, 6
// digits, SHA1.
func generateTotpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period:    MfaTotpPeriodInSeconds,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}
	return code
}

// newLockoutTestFixture creates an isolated org/application/user (with TOTP
// MFA enrolled) suitable for exercising the MFA-passcode signin path. The
// application's failed-signin limit is set low (3) so the test can drive the
// account into a locked state in a handful of attempts.
func newLockoutTestFixture(t *testing.T, suffix string) (*User, string) {
	t.Helper()

	orgName := "niro-mfa-org-" + suffix
	appName := "niro-mfa-app-" + suffix
	userName := "niro-mfa-user-" + suffix

	org := &Organization{
		Owner:        "admin",
		Name:         orgName,
		DisplayName:  orgName,
		PasswordType: "plain",
	}
	if ok, err := AddOrganization(org); err != nil || !ok {
		t.Fatalf("AddOrganization failed: ok=%v err=%v", ok, err)
	}

	app := &Application{
		Owner:                  "admin",
		Name:                   appName,
		Organization:           orgName,
		EnablePassword:         true,
		FailedSigninLimit:      3,
		FailedSigninFrozenTime: 15,
	}
	if ok, err := AddApplication(app); err != nil || !ok {
		t.Fatalf("AddApplication failed: ok=%v err=%v", ok, err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Casdoor",
		AccountName: orgName + "/" + userName,
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP secret: %v", err)
	}

	user := &User{
		Owner:             orgName,
		Name:              userName,
		Password:          "Passw0rd!",
		PasswordType:      "plain",
		SignupApplication: appName,
		Type:              "normal-user",
		TotpSecret:        key.Secret(),
	}
	if ok, err := AddUser(user, "en"); err != nil || !ok {
		t.Fatalf("AddUser failed: ok=%v err=%v", ok, err)
	}

	fetched, err := GetUser(orgName + "/" + userName)
	if err != nil || fetched == nil {
		t.Fatalf("GetUser failed: user=%v err=%v", fetched, err)
	}

	return fetched, key.Secret()
}

// TestCheckMfaPasscodeLockout is the regression test for TC-01E1D881: no
// rate limiting or lockout on TOTP second-factor verification during login.
//
// Invariant under test: repeated wrong TOTP passcodes against a user's
// pending-MFA login must be rate limited/locked out the same way repeated
// wrong passwords already are (object.CheckPassword / SigninWrongTimes /
// FailedSigninLimit) -- an attacker holding a valid password must not be
// able to submit unlimited guesses at the second factor.
func TestCheckMfaPasscodeLockout(t *testing.T) {
	setUpIsolatedTestOrmer(t)

	victim, secret := newLockoutTestFixture(t, "victim")
	mfaUtil := GetMfaUtil(TotpType, victim.GetMfaProps(TotpType, false))
	if mfaUtil == nil {
		t.Fatal("GetMfaUtil returned nil for a user with TOTP enabled")
	}

	// Step 1: submit wrong passcodes, one per counter tick so each is a
	// distinct, deterministically-wrong 6-digit code.
	wrongAttempts := 0
	var lastErr error
	for i := 0; i < 10; i++ {
		wrongCode := fmt.Sprintf("%06d", (i+1)*111111%1000000)
		if wrongCode == generateTotpCode(t, secret, time.Now()) {
			// Vanishingly unlikely, but stay deterministic if it ever happens.
			continue
		}

		lastErr = CheckMfaPasscode(victim, mfaUtil, wrongCode, "en")
		if lastErr == nil {
			t.Fatalf("attempt %d: wrong passcode %q was accepted", i, wrongCode)
		}

		signinErr, ok := lastErr.(*SigninError)
		if !ok {
			t.Fatalf("attempt %d: expected *SigninError, got %T: %v", i, lastErr, lastErr)
		}

		wrongAttempts++
		if signinErr.Reason == SigninReasonAccountFrozen {
			break
		}
		if signinErr.Reason != SigninReasonWrongPassword {
			t.Fatalf("attempt %d: unexpected signin error reason %q", i, signinErr.Reason)
		}

		// Reload the user the same way the controller does on every request
		// in the pending-MFA flow (object.GetUser(c.getMfaUserSession())).
		reloaded, err := GetUser(victim.GetId())
		if err != nil || reloaded == nil {
			t.Fatalf("attempt %d: GetUser failed: %v", i, err)
		}
		victim = reloaded
	}

	// Step 2: the invariant -- the account must have been locked well before
	// 10 unthrottled wrong guesses (the application's FailedSigninLimit is 3).
	signinErr, ok := lastErr.(*SigninError)
	if !ok || signinErr.Reason != SigninReasonAccountFrozen {
		t.Fatalf("account was not locked out after %d wrong passcode attempts (last err: %v)", wrongAttempts, lastErr)
	}
	if wrongAttempts > 5 {
		t.Fatalf("account allowed %d wrong passcode attempts before lockout, want <= 5", wrongAttempts)
	}

	// Step 3: prove the lockout actually blocks the *correct* code too --
	// otherwise "lockout" would be theater that a patient attacker can
	// still walk straight through.
	reloaded, err := GetUser(victim.GetId())
	if err != nil || reloaded == nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	victim = reloaded

	correctCode := generateTotpCode(t, secret, time.Now())
	err = CheckMfaPasscode(victim, mfaUtil, correctCode, "en")
	if err == nil {
		t.Fatal("INVARIANT VIOLATED: correct TOTP code was accepted on a locked-out account")
	}
	if signinErr, ok := err.(*SigninError); !ok || signinErr.Reason != SigninReasonAccountFrozen {
		t.Fatalf("expected account-frozen error for correct code on locked account, got: %v", err)
	}

	// Positive control: a fresh, never-attacked user on the same
	// application logs in with the correct code on the first try, and the
	// lockout counter is reset (proving the fix doesn't break legitimate
	// MFA login, and isn't a broken environment producing false negatives).
	control, controlSecret := newLockoutTestFixture(t, "control")
	controlMfaUtil := GetMfaUtil(TotpType, control.GetMfaProps(TotpType, false))
	if controlMfaUtil == nil {
		t.Fatal("GetMfaUtil returned nil for control user")
	}

	controlCode := generateTotpCode(t, controlSecret, time.Now())
	if err := CheckMfaPasscode(control, controlMfaUtil, controlCode, "en"); err != nil {
		t.Fatalf("control: legitimate first-try correct passcode was rejected: %v", err)
	}

	reloadedControl, err := GetUser(control.GetId())
	if err != nil || reloadedControl == nil {
		t.Fatalf("GetUser failed for control user: %v", err)
	}
	if reloadedControl.SigninWrongTimes != 0 {
		t.Fatalf("control: expected signin_wrong_times to stay 0 after a correct passcode, got %d", reloadedControl.SigninWrongTimes)
	}
}
