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
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xorm-io/xorm"
)

// seedCounter guarantees a unique (owner, name) primary key per seeded record so
// repeated seeds in one test never collide.
var seedCounter int64

// setupVerificationTestOrmer stands up a fully isolated, in-memory sqlite engine
// with just the verification_record table. It never touches the app's real
// database, config, or the running pentest target — the whole point is a
// hermetic unit that exercises the signup verification-code check path.
func setupVerificationTestOrmer(t *testing.T) func() {
	t.Helper()

	// CheckVerificationCode reads verificationCodeTimeout from config; in this
	// hermetic test there is no app.conf, so provide it via env (GetConfigString
	// consults os.LookupEnv first). 10 minutes matches conf/app.conf.
	prevTimeout, hadTimeout := os.LookupEnv("verificationCodeTimeout")
	if err := os.Setenv("verificationCodeTimeout", "10"); err != nil {
		t.Fatalf("failed to set verificationCodeTimeout: %v", err)
	}

	engine, err := xorm.NewEngine("sqlite", "file:verify_signup_throttle?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to create sqlite test engine: %v", err)
	}
	if err = engine.Sync2(new(VerificationRecord)); err != nil {
		t.Fatalf("failed to sync VerificationRecord table: %v", err)
	}

	prevOrmer := ormer
	ormer = &Ormer{Engine: engine}

	// Isolate the in-memory per-IP throttle map so state cannot leak between tests.
	verifyCodeIpErrorMapLock.Lock()
	prevIPMap := verifyCodeIpErrorMap
	verifyCodeIpErrorMap = map[string]*verifyCodeErrorInfo{}
	verifyCodeIpErrorMapLock.Unlock()

	return func() {
		ormer = prevOrmer
		_ = engine.Close()

		verifyCodeIpErrorMapLock.Lock()
		verifyCodeIpErrorMap = prevIPMap
		verifyCodeIpErrorMapLock.Unlock()

		if hadTimeout {
			_ = os.Setenv("verificationCodeTimeout", prevTimeout)
		} else {
			_ = os.Unsetenv("verificationCodeTimeout")
		}
	}
}

// seedVerificationRecord inserts a valid, unused, in-window verification record
// for dest with the given correct code (mirrors what /api/send-verification-code
// would have created in a real deployment).
func seedVerificationRecord(t *testing.T, dest, correctCode string) {
	t.Helper()
	rec := &VerificationRecord{
		Owner:    "test",
		Name:     fmt.Sprintf("vr-%s-%d", dest, atomic.AddInt64(&seedCounter, 1)),
		Receiver: dest,
		Code:     correctCode,
		Time:     time.Now().Unix(),
		IsUsed:   false,
		User:     "",
		Provider: "test-provider",
	}
	if _, err := ormer.Engine.Insert(rec); err != nil {
		t.Fatalf("failed to seed verification record: %v", err)
	}
}

// TestSignupVerificationCodeThrottle pins the security invariant behind
// TC-CAF265EC: the signup email/phone verification-code check
// (CheckSignupVerificationCode — the exact seam ApiController.Signup calls for
// both authForm.EmailCode and authForm.PhoneCode) must throttle repeated wrong
// guesses per (client-IP, destination) — 5 wrong attempts, then a lockout —
// exactly like the password-reset and login code checks. Before the fix this
// seam called object.CheckVerificationCode directly, which throttles nothing;
// this test fails (never freezes) against that behavior and passes once the seam
// routes through the per-IP limiter.
func TestSignupVerificationCodeThrottle(t *testing.T) {
	cleanup := setupVerificationTestOrmer(t)
	defer cleanup()

	const (
		dest        = "ratetest@acme.test"
		correctCode = "654321"
		clientIP    = "203.0.113.7"
		lang        = "en"
	)
	seedVerificationRecord(t, dest, correctCode)

	// Baseline (green): a legitimate correct code verifies through the signup
	// check, so any red below is the invariant itself, not a broken setup.
	if err := CheckSignupVerificationCode(clientIP, dest, correctCode, lang); err != nil {
		t.Fatalf("baseline: correct code should verify through the signup path, got error: %v", err)
	}

	// Re-seed: the successful check above resets the throttle counter, and a fresh
	// unused record keeps the wrong-code branch reachable for the brute-force.
	seedVerificationRecord(t, dest, correctCode)

	// Invariant: after defaultVerifyCodeIpLimit (5) wrong guesses for the same
	// (IP, dest), further guesses must be rejected with a lockout — not merely
	// "wrong code". We make 8 wrong guesses and require that at least one (the 6th
	// onward) is frozen. On the pre-fix code (raw CheckVerificationCode) this
	// never happens, so the test goes red exactly on the vulnerability.
	frozen := false
	for i := 0; i < 8; i++ {
		err := CheckSignupVerificationCode(clientIP, dest, "000000", lang)
		if err == nil {
			t.Fatalf("wrong code #%d unexpectedly succeeded", i+1)
		}
		if strings.Contains(err.Error(), "wait for") && strings.Contains(err.Error(), "minutes") {
			frozen = true
			break
		}
	}
	if !frozen {
		t.Fatalf("signup verification path did NOT lock out after repeated wrong guesses: " +
			"the (IP, dest) throttle never froze within 8 attempts")
	}

	// Control — a legitimate guesser from a DIFFERENT IP is unaffected by the
	// first IP's lockout, proving the throttle is scoped per (IP, dest) and does
	// not globally break signup verification.
	seedVerificationRecord(t, dest, correctCode)
	if err := CheckSignupVerificationCode("198.51.100.9", dest, correctCode, lang); err != nil {
		t.Fatalf("control: a fresh client IP should still verify the correct code, got error: %v", err)
	}
}
