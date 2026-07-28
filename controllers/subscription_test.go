// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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

// TestSubscriptionAccessForbidden pins the security invariant behind
// GET /api/get-subscription (TC-C6E52E36):
//
//	An anonymous caller, or any authenticated user who is not the
//	subscription's owner/subscriber, must not be able to read another
//	user's subscription record just by knowing or guessing its id.
//
// It mirrors the ownership check the sibling GetOrder/GetPayment handlers
// already apply (controllers/order.go, controllers/payment.go): a non-admin
// caller may only read a subscription whose Owner matches their own tenant
// and whose User matches their own username.
func TestSubscriptionAccessForbidden(t *testing.T) {
	aliceSub := &object.Subscription{Owner: "niro-test", Name: "sub-alice", User: "alice"}

	cases := []struct {
		name             string
		sessionUserOwner string
		sessionUserName  string
		subscription     *object.Subscription
		want             bool // true = access must be forbidden
	}{
		// --- The invariant: non-owner reads are forbidden ---
		{
			name:             "different user in same org is forbidden",
			sessionUserOwner: "niro-test",
			sessionUserName:  "bob",
			subscription:     aliceSub,
			want:             true,
		},
		{
			name:             "anonymous caller (empty session identity) is forbidden",
			sessionUserOwner: "",
			sessionUserName:  "",
			subscription:     aliceSub,
			want:             true,
		},
		{
			name:             "different org entirely is forbidden",
			sessionUserOwner: "other-org",
			sessionUserName:  "alice",
			subscription:     aliceSub,
			want:             true,
		},

		// --- Healthy baseline: the legitimate owner can still read it ---
		{
			name:             "owner reading their own subscription is allowed",
			sessionUserOwner: "niro-test",
			sessionUserName:  "alice",
			subscription:     aliceSub,
			want:             false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := subscriptionAccessForbidden(tc.sessionUserOwner, tc.sessionUserName, tc.subscription)
			if got != tc.want {
				t.Fatalf("subscriptionAccessForbidden(session=%s/%s, subscription owner=%s user=%s) = %v, want %v",
					tc.sessionUserOwner, tc.sessionUserName, tc.subscription.Owner, tc.subscription.User, got, tc.want)
			}
		})
	}
}
