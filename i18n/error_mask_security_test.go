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

package i18n

import (
	"fmt"
	"testing"
)

// Security invariant (account-existence enumeration, TC-BC6577A4):
//
// The unauthenticated sign-in and forgot-password flows must not reveal whether
// a given username/email exists. Casdoor collapses the distinguishing error
// strings into one generic message via the error mask in Translate(). This test
// asserts that, at the shipped default configuration, the "user does not exist"
// strings those flows emit are indistinguishable from the "wrong password/code"
// string an existing account receives.
//
// The keys below are the exact strings the flows emit:
//   - login,  user missing:   "general:The user: %s doesn't exist"      (object/check.go)
//   - login,  wrong password: "check:password or code is incorrect, you have %s remaining chances"
//     (object/check_util.go)
//   - forget, user missing:   "verification:the user does not exist, please sign up first"
//     (controllers/verification.go)
//
// If any translates to a client string different from the generic
// "password or code is incorrect", an unauthenticated caller can tell existing
// accounts from non-existing ones — the enumeration oracle. This asserts the
// mask both is on by default AND covers all three keys.
func TestErrorMaskHidesAccountExistence(t *testing.T) {
	const lang = "en"

	// Exercise the mask exactly as shipped: driven by defaultEnableErrorMask,
	// not force-enabled by the test. That is what makes this a regression test
	// for the default deployment, not merely for an opt-in flag.
	prev := enableErrorMask
	enableErrorMask = defaultEnableErrorMask
	defer func() { enableErrorMask = prev }()

	// The client-visible string every identity-check failure must reduce to.
	// We compare the CLIENT-VISIBLE text, i.e. after the fmt.Sprintf the callers
	// apply — the mask appends a "%.s" verb to keyed messages that carry a format
	// argument, and that verb is consumed by the caller's Sprintf. Modelling the
	// real call site is what makes this assert the true wire invariant.
	//
	// Legitimate/green control: the generic message must resolve to a real
	// translated string, proving i18n plumbing is healthy so any failure below is
	// the invariant, not a broken environment.
	generic := Translate(lang, "check:password or code is incorrect")
	if generic != "password or code is incorrect" {
		t.Fatalf("baseline generic message did not resolve as expected: got %q", generic)
	}

	leakingKeys := []struct {
		name string
		// client renders the key exactly as the production call site does.
		client func() string
	}{
		{
			// object/check.go: fmt.Sprintf(Translate(key), util.GetId(org, user))
			name: "login user-not-found must match wrong-password response",
			client: func() string {
				return fmt.Sprintf(Translate(lang, "general:The user: %s doesn't exist"), "acme/alice")
			},
		},
		{
			// object/check_util.go: fmt.Sprintf(Translate(key), remainingChances)
			name: "login wrong-password-with-chances must reduce to the generic message",
			client: func() string {
				return fmt.Sprintf(Translate(lang, "check:password or code is incorrect, you have %s remaining chances"), "4")
			},
		},
		{
			// controllers/verification.go: c.T(key) — no Sprintf wrapper.
			name: "forget-password user-not-found must match wrong-password response",
			client: func() string {
				return Translate(lang, "verification:the user does not exist, please sign up first")
			},
		},
	}

	for _, tc := range leakingKeys {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.client()
			if got != generic {
				t.Errorf("account-existence leak: client-visible message %q differs from the generic %q (an unauthenticated caller can distinguish accounts)",
					got, generic)
			}
		})
	}
}
