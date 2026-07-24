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
	"errors"
	"strings"
	"testing"
	"time"
)

// This suite locks in the security invariant behind TC-44B59C9F: the login-time
// second factor (TOTP one-time code) must be rate-limited the same way the wrong-
// password step is — a "remaining chances" warning after N wrong guesses, then a
// timed lockout — so an attacker who already has the victim's password cannot
// brute-force the 6-digit code with unlimited guesses.
//
// It drives evalMfaSigninAttempt, the pure decision core that CheckMfaSigninErrorTimes
// runs on every /api/login passcode attempt, with no database. now is injected so the
// cooldown math is deterministic.

// totpVerifyErr is the crypto-check result for a wrong TOTP code, mirroring what
// object/mfa_totp.go TotpMfa.Verify() returns.
var totpVerifyErr = errors.New("totp passcode error")

const (
	testLimit  = DefaultFailedSigninLimit      // 5
	testFrozen = DefaultFailedSigninFrozenTime // 15 minutes
)

// oldUnprotectedVerify reproduces the vulnerable pre-fix passcode branch: it calls the
// crypto check directly with NO attempt bookkeeping. It exists only to make the RED
// state explicit and self-documenting — the fixed path (evalMfaSigninAttempt) must NOT
// behave like this.
func oldUnprotectedVerify(user *User, verifyErr error) error {
	// no SigninWrongTimes check, no recordSigninErrorInfo — just the raw crypto result.
	return verifyErr
}

// TestMfaPasscodeUnprotectedPathIsBrute forceable documents the bug: with the old
// direct-Verify behavior, unlimited wrong guesses are accepted, all returning the same
// raw error and never locking out.
func TestMfaPasscodeUnprotectedPathIsBruteforceable(t *testing.T) {
	user := &User{Owner: "acme", Name: "victim"}
	lockoutSeen := false
	for i := 1; i <= 50; i++ {
		err := oldUnprotectedVerify(user, totpVerifyErr)
		if err == nil {
			t.Fatalf("wrong passcode unexpectedly accepted at attempt %d", i)
		}
		if isLockoutMessage(err.Error()) {
			lockoutSeen = true
			break
		}
	}
	if lockoutSeen {
		t.Fatalf("sanity: the unprotected path is not supposed to lock out — the reproduction is wrong")
	}
	// This is the vulnerability: 50 wrong guesses, no lockout, counter never moved.
	if user.SigninWrongTimes != 0 {
		t.Fatalf("unprotected path unexpectedly tracked attempts: SigninWrongTimes=%d", user.SigninWrongTimes)
	}
	t.Logf("reproduced TC-44B59C9F: 50 wrong TOTP guesses on the unprotected path, no lockout, counter never incremented")
}

// TestMfaPasscodeIsRateLimited is the core regression test: the FIXED path must warn,
// then lock out, exactly like the password step. This FAILS (loops forever without a
// lockout, then trips the assertion) against any implementation that just calls Verify
// directly — it is green only because evalMfaSigninAttempt applies the counter+freeze.
func TestMfaPasscodeIsRateLimited(t *testing.T) {
	user := &User{Owner: "acme", Name: "victim"}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	var lastMsg string
	lockedOutAt := 0
	prevWrongTimes := 0
	for i := 1; i <= 50; i++ {
		out := evalMfaSigninAttempt(user, totpVerifyErr, testLimit, testFrozen, false, now, "en")
		if out.err == nil {
			t.Fatalf("wrong passcode must never be accepted; got acceptance at attempt %d", i)
		}
		lastMsg = out.err.Error()

		// While the account is frozen the crypto check must not even be consulted.
		if isFrozenMessage(lastMsg) {
			lockedOutAt = i
			break
		}
		// Before the limit each wrong guess must be COUNTED — the failure counter that
		// drives the freeze must advance on every attempt. We assert the durable
		// bookkeeping mechanism rather than the exact user-facing wording: a separate
		// hardening (account-existence masking, TC-BC6577A4) may collapse the pre-lockout
		// "remaining chances" detail into a generic message, but the rate-limit counter —
		// and therefore the approaching lockout — must hold regardless of the message text.
		if user.SigninWrongTimes <= prevWrongTimes {
			t.Fatalf("attempt %d: wrong passcode was not counted toward lockout (SigninWrongTimes stuck at %d, msg %q)", i, user.SigninWrongTimes, lastMsg)
		}
		prevWrongTimes = user.SigninWrongTimes
	}

	if lockedOutAt == 0 {
		t.Fatalf("INVARIANT VIOLATED: sent 50 wrong TOTP guesses, the second factor never locked out (last msg %q). "+
			"The passcode step is un-rate-limited and can be brute-forced.", lastMsg)
	}
	if lockedOutAt > testLimit+1 {
		t.Fatalf("lockout arrived too late: at attempt %d, expected by attempt %d", lockedOutAt, testLimit+1)
	}
	t.Logf("second factor locked out at attempt %d with message %q", lockedOutAt, lastMsg)

	// A frozen user stays frozen: further guesses keep returning the freeze message
	// and never fall through to the crypto check.
	frozen := evalMfaSigninAttempt(user, totpVerifyErr, testLimit, testFrozen, false, now, "en")
	if !isFrozenMessage(frozen.err.Error()) {
		t.Fatalf("expected continued lockout on a frozen user, got %q", frozen.err)
	}
	// Even a *correct* passcode is refused while frozen — the whole point of the lockout.
	frozenButCorrect := evalMfaSigninAttempt(user, nil, testLimit, testFrozen, false, now, "en")
	if frozenButCorrect.err == nil || !isFrozenMessage(frozenButCorrect.err.Error()) {
		t.Fatalf("a correct passcode must still be refused while frozen, got %v", frozenButCorrect.err)
	}
}

// TestMfaPasscodeCorrectCodeStillAccepted is the paired positive control (matching the
// PoC's green control): on an un-frozen session a correct code completes login. This
// proves the red above is the missing rate limit, not a blanket rejection.
func TestMfaPasscodeCorrectCodeStillAccepted(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	// Fresh session, correct code -> accepted.
	fresh := &User{Owner: "acme", Name: "victim"}
	if out := evalMfaSigninAttempt(fresh, nil, testLimit, testFrozen, false, now, "en"); out.err != nil {
		t.Fatalf("correct passcode on a fresh session must be accepted, got %v", out.err)
	}

	// A few wrong guesses (below the limit), then the correct code -> accepted and the
	// failure counter is cleared.
	user := &User{Owner: "acme", Name: "victim"}
	for i := 0; i < testLimit-1; i++ {
		if out := evalMfaSigninAttempt(user, totpVerifyErr, testLimit, testFrozen, false, now, "en"); out.err == nil {
			t.Fatalf("wrong passcode unexpectedly accepted")
		}
	}
	if user.SigninWrongTimes != testLimit-1 {
		t.Fatalf("expected %d recorded failures, got %d", testLimit-1, user.SigninWrongTimes)
	}
	out := evalMfaSigninAttempt(user, nil, testLimit, testFrozen, false, now, "en")
	if out.err != nil {
		t.Fatalf("correct passcode before lockout must be accepted, got %v", out.err)
	}
	if user.SigninWrongTimes != 0 {
		t.Fatalf("a successful second factor must reset the failure counter, still %d", user.SigninWrongTimes)
	}
}

// TestMfaPasscodeLockoutExpires confirms the lockout is a cooldown, not a permanent
// ban: once the frozen window elapses the user may try again.
func TestMfaPasscodeLockoutExpires(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	user := &User{
		Owner:               "acme",
		Name:                "victim",
		SigninWrongTimes:    testLimit,
		LastSigninWrongTime: now.Format(time.RFC3339),
	}

	// Still frozen right after the limit.
	if out := evalMfaSigninAttempt(user, nil, testLimit, testFrozen, false, now, "en"); !isFrozenMessage(errString(out.err)) {
		t.Fatalf("expected frozen immediately after limit, got %v", out.err)
	}

	// After the cooldown a correct code is accepted again.
	later := now.Add(time.Duration(testFrozen+1) * time.Minute)
	if out := evalMfaSigninAttempt(user, nil, testLimit, testFrozen, false, later, "en"); out.err != nil {
		t.Fatalf("after the cooldown a correct passcode must be accepted, got %v", out.err)
	}
	if user.SigninWrongTimes != 0 {
		t.Fatalf("counter must reset after a successful post-cooldown login, got %d", user.SigninWrongTimes)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func isLockoutMessage(msg string) bool {
	return isRemainingChancesMessage(msg) || isFrozenMessage(msg)
}

func isRemainingChancesMessage(msg string) bool {
	return strings.Contains(strings.ToLower(msg), "remaining chances")
}

func isFrozenMessage(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "please wait") && strings.Contains(lower, "too many times")
}
