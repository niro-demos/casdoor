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

package controllers

import "testing"

func TestAnonymousAuthFailuresDoNotRevealAccountState(t *testing.T) {
	tests := []struct {
		name       string
		failureFor func(bool) string
	}{
		{
			name: "password login",
			failureFor: func(accountExists bool) string {
				if accountExists {
					return anonymousLoginFailure("password or code is incorrect, you have 4 remaining chances")
				}
				return anonymousLoginFailure("The user: built-in/missing doesn't exist")
			},
		},
		{
			name: "WebAuthn begin",
			failureFor: func(accountExists bool) string {
				if accountExists {
					return anonymousWebAuthnFailure("Found no credentials for this user")
				}
				return anonymousWebAuthnFailure("The user: built-in/missing doesn't exist")
			},
		},
		{
			name: "password recovery",
			failureFor: func(accountExists bool) string {
				if accountExists {
					return anonymousRecoveryResult("please add an Email provider")
				}
				return anonymousRecoveryResult("the user does not exist, please sign up first")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing := tt.failureFor(true)
			missing := tt.failureFor(false)
			if existing == "" {
				t.Fatal("anonymous failure must return a useful generic response")
			}
			if existing != missing {
				t.Fatalf("account state is distinguishable: existing=%q missing=%q", existing, missing)
			}
		})
	}
}
