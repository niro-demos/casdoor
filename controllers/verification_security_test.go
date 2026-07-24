// Copyright 2024 The Casdoor Authors. All Rights Reserved.
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
	"testing"

	"github.com/casdoor/casdoor/object"
)

// Account-existence enumeration guard for the forgot-password flow (TC-BC6577A4).
//
// SendVerificationCode()'s forget branch used to fast-fail on a missing/deleted
// "checkUser" with the distinct string "the user does not exist, please sign up
// first", whereas an existing user proceeded to the dest/email validation and
// failed later with a different string ("Email is invalid"). That difference is
// an enumeration oracle for an unauthenticated caller.
//
// The fix routes the missing/deleted case through the same nil-user continuation
// the flow already uses, so both existing and non-existing checkUser values reach
// the identical downstream validation. forgetCheckUserResolved() is that decision
// point: it may only report whether a real, usable account resolved — a false
// result is handled by the caller by continuing with a nil user, never by a
// distinct user-facing message.
//
// This test pins the decision so a future refactor cannot reintroduce a
// "does-not-exist" fast-fail: a missing user and a soft-deleted user must be
// indistinguishable from each other, and both must be treated as "not resolved"
// (i.e. continue with nil), never as "reject early".
func TestForgetCheckUserDoesNotLeakExistence(t *testing.T) {
	present := &object.User{Name: "alice", IsDeleted: false}
	deleted := &object.User{Name: "alice", IsDeleted: true}

	cases := []struct {
		name     string
		user     *object.User
		resolved bool // true only for a real, present, usable account
	}{
		{name: "present account resolves", user: present, resolved: true},
		{name: "soft-deleted account must not resolve", user: deleted, resolved: false},
		{name: "missing account must not resolve", user: nil, resolved: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := forgetCheckUserResolved(tc.user); got != tc.resolved {
				t.Fatalf("forgetCheckUserResolved(%v) = %v, want %v", tc.user, got, tc.resolved)
			}
		})
	}

	// Invariant: the two "does not exist to this flow" states — missing and
	// soft-deleted — must be indistinguishable from each other. If they diverged,
	// the caller could branch on them and re-expose an existence oracle.
	if forgetCheckUserResolved(nil) != forgetCheckUserResolved(deleted) {
		t.Fatalf("missing and soft-deleted users are distinguishable: %v vs %v",
			forgetCheckUserResolved(nil), forgetCheckUserResolved(deleted))
	}
}
