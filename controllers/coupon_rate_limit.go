// Copyright 2025 The Casdoor Authors. All Rights Reserved.
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
	"sync"
	"time"
)

// Coupon-check brute-force throttling.
//
// /api/validate-coupon lets any authenticated user probe whether a coupon
// code exists (the response shape differs for a hit vs. a miss), so without
// a limit a logged-in attacker can enumerate a store's active coupon codes
// at network speed. This mirrors the failed-attempt-counter /
// temporary-lockout shape already used for signin (object/check_util.go),
// but is self-contained (in-memory, per authenticated user) so it needs no
// schema change and does not touch the login/application config path.
const (
	// couponValidateFailureLimit is the number of failed coupon checks a
	// single authenticated user may make within couponValidateFailureWindow
	// before being locked out. Picked from the remediation guidance's
	// suggested 5-10 failed checks per minute.
	couponValidateFailureLimit = 10

	// couponValidateFailureWindow is the rolling window failed attempts are
	// counted over.
	couponValidateFailureWindow = time.Minute

	// couponValidateLockoutPeriod is how long a user is locked out of the
	// endpoint once couponValidateFailureLimit is reached.
	couponValidateLockoutPeriod = time.Minute
)

type couponAttemptState struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

var (
	couponAttemptMu     sync.Mutex
	couponAttemptStates = map[string]*couponAttemptState{}
)

// couponValidateAllow reports whether userName may attempt another coupon
// validation at time now. When it may not, it also returns the number of
// whole seconds remaining until the lockout clears.
func couponValidateAllow(userName string, now time.Time) (bool, int64) {
	couponAttemptMu.Lock()
	defer couponAttemptMu.Unlock()

	state := couponAttemptStates[userName]
	if state == nil {
		return true, 0
	}

	if now.Before(state.lockedUntil) {
		retryAfter := int64(state.lockedUntil.Sub(now) / time.Second)
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}

	return true, 0
}

// couponValidateRecordFailure records a failed coupon-validation attempt by
// userName at time now, locking the user out for couponValidateLockoutPeriod
// once couponValidateFailureLimit failures land inside
// couponValidateFailureWindow.
func couponValidateRecordFailure(userName string, now time.Time) {
	couponAttemptMu.Lock()
	defer couponAttemptMu.Unlock()

	state := couponAttemptStates[userName]
	if state == nil || now.Sub(state.windowStart) > couponValidateFailureWindow {
		state = &couponAttemptState{windowStart: now}
		couponAttemptStates[userName] = state
	}

	state.failures++
	if state.failures >= couponValidateFailureLimit {
		state.lockedUntil = now.Add(couponValidateLockoutPeriod)
	}
}

// couponValidateRecordSuccess clears failure tracking for userName after a
// successful coupon validation, so legitimate use never accumulates toward
// a lockout.
func couponValidateRecordSuccess(userName string) {
	couponAttemptMu.Lock()
	defer couponAttemptMu.Unlock()

	delete(couponAttemptStates, userName)
}
