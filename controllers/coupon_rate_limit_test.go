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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
)

// newValidateCouponController builds a real *ApiController wired up to run
// ValidateCoupon() the same way Beego's router would, without needing a live
// HTTP server: it injects "currentUserId" the way ApiFilter normally would
// (see ApiController.GetSessionUsername in controllers/base.go), so no
// session store is required to authenticate the caller.
func newValidateCouponController(t *testing.T, currentUserId string) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()

	// An empty couponCode makes object.GetCouponByCode (object/coupon.go)
	// return (nil, nil) immediately without touching the database - the
	// same "coupon not found" outcome a real wrong guess produces, just
	// reachable without a live DB. That keeps this test exercising the
	// production ValidateCoupon() controller end-to-end instead of a
	// re-implementation of it.
	body, err := json.Marshal(map[string]interface{}{
		"owner":      "niro-test",
		"couponCode": "",
		"products":   []string{},
		"amount":     100,
		"currency":   "USD",
	})
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/validate-coupon", nil)
	rw := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(rw, req)
	ctx.Input.SetData("currentUserId", currentUserId)
	ctx.Input.RequestBody = body

	c := &ApiController{}
	c.Init(ctx, "ApiController", "ValidateCoupon", nil)

	return c, rw
}

// callValidateCoupon runs one real ValidateCoupon() request as user and
// reports whether the endpoint refused the attempt for being rate-limited.
func callValidateCoupon(t *testing.T, user string) (throttled bool, status, msg string) {
	t.Helper()

	c, rw := newValidateCouponController(t, user)
	c.ValidateCoupon()

	var resp map[string]interface{}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response body is not JSON: %v (body=%q)", err, rw.Body.String())
	}

	status, _ = resp["status"].(string)
	msg, _ = resp["msg"].(string)
	lower := strings.ToLower(msg)
	throttled = strings.Contains(lower, "too many") || strings.Contains(lower, "rate limit") ||
		strings.Contains(lower, "locked") || strings.Contains(lower, "try again")

	return throttled, status, msg
}

// TestValidateCouponDoesNotThrottleASingleAttempt is the paired "control"
// for the brute-force test below: a lone, first-ever coupon check by a user
// must be treated as an ordinary "coupon not found" business error, not a
// rate-limit rejection - proving any observed throttling is the invariant
// firing, not a broken test environment.
func TestValidateCouponDoesNotThrottleASingleAttempt(t *testing.T) {
	const user = "niro-test/throttle-test-control"

	throttled, status, msg := callValidateCoupon(t, user)
	if throttled {
		t.Fatalf("a user's first-ever coupon check must not be throttled, got status=%q msg=%q", status, msg)
	}
	if status != "error" {
		t.Fatalf("expected the ordinary coupon-not-found business error for a first attempt, got status=%q msg=%q", status, msg)
	}
}

// TestValidateCouponThrottlesRepeatedFailedGuesses is the regression test
// for TC-F04468A7: a logged-in standard user must not be able to
// unlimitedly guess a store's coupon codes on /api/validate-coupon with no
// throttling or lockout.
//
// It drives the real ApiController.ValidateCoupon() the way the router
// does, as one authenticated user, repeatedly guessing wrong coupon codes -
// mirroring niro/findings/TC-F04468A7/poc.go (30 sequential wrong guesses,
// all HTTP 200/no throttle on the unfixed endpoint), translated into this
// project's own controller-test shape instead of raw HTTP.
func TestValidateCouponThrottlesRepeatedFailedGuesses(t *testing.T) {
	const user = "niro-test/throttle-test-attacker"
	const guesses = 30

	for i := 0; i < guesses; i++ {
		throttled, status, msg := callValidateCoupon(t, user)
		if throttled {
			t.Logf("guess %d: throttled as expected (status=%q msg=%q)", i, status, msg)
			return
		}
	}

	t.Fatalf("invariant violated: %d consecutive wrong coupon-code guesses from the same authenticated user were all let through /api/validate-coupon with no throttling or lockout", guesses)
}

// TestValidateCouponThrottleIsPerUserAndClearsOnSuccess guards the
// legitimate-use side of the fix: the lockout must not bleed across
// different users sharing the endpoint, and a successful check must clear a
// user's own failure count instead of leaving them permanently penalized
// for earlier mistakes (e.g. typos) once they get the code right.
func TestValidateCouponThrottleIsPerUserAndClearsOnSuccess(t *testing.T) {
	const victim = "niro-test/throttle-test-victim"
	const bystander = "niro-test/throttle-test-bystander"

	now := time.Now()
	for i := 0; i < couponValidateFailureLimit; i++ {
		couponValidateRecordFailure(victim, now)
	}
	t.Cleanup(func() { couponValidateRecordSuccess(victim) })

	if allowed, _ := couponValidateAllow(victim, now); allowed {
		t.Fatalf("expected %q to be locked out after %d failures", victim, couponValidateFailureLimit)
	}

	if allowed, retryAfter := couponValidateAllow(bystander, now); !allowed {
		t.Fatalf("a different user (%q) must not be affected by another user's lockout, got blocked with retryAfter=%d", bystander, retryAfter)
	}

	// A successful validation (e.g. the user finally enters the right code)
	// must reset their failure count rather than leaving them locked out.
	couponValidateRecordSuccess(victim)
	if allowed, retryAfter := couponValidateAllow(victim, now); !allowed {
		t.Fatalf("a successful coupon validation must clear the user's failure count, got still blocked with retryAfter=%d", retryAfter)
	}
}
