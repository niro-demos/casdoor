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

import "testing"

// TestAddTransactionWalletCreditRequiresGlobalAdmin asserts the security invariant
// for POST /api/add-transaction:
//
//	A `tag == "User"` transaction directly credits a user's spendable wallet balance
//	(object.updateBalanceForTransaction -> object.UpdateUserBalance). That balance
//	increase must only be reachable by a GLOBAL admin (built-in org) acting as the
//	server, or by the internal payment-provider callback path
//	(object.AddInternalPaymentTransaction). A mere ORG admin (User.IsAdmin == true in a
//	non-built-in org) — a role also used as an ordinary purchasing customer — must NOT
//	be able to credit a wallet balance through the generic add-transaction endpoint,
//	because no real payment has occurred.
//
// The endpoint's only pre-fix authorization gate was authz.IsAllowed, whose
// `user.IsAdmin && subOwner == objOwner` branch grants an org-admin blanket access to
// every mutation scoped to their own org — including add-transaction — letting them
// mint arbitrary balance for themselves. The fix narrows the balance-crediting
// (`tag == "User"`) path to a global admin only; canCreditWalletBalance is that gate.
//
// This test is hermetic: it exercises the pure authorization decision directly, with
// no database or live target, so it runs under `go test ./...`.
func TestAddTransactionWalletCreditRequiresGlobalAdmin(t *testing.T) {
	cases := []struct {
		name          string
		tag           string
		isGlobalAdmin bool
		wantAllowed   bool
	}{
		{
			// The vulnerability: an org-admin (not a global admin) self-crediting
			// wallet balance via tag=="User" must be rejected.
			name:          "org-admin crediting user wallet balance is rejected",
			tag:           "User",
			isGlobalAdmin: false,
			wantAllowed:   false,
		},
		{
			// The internal payment-callback path runs as the server / global admin;
			// legitimate wallet credits stay allowed, so the fix is specific.
			name:          "global admin crediting user wallet balance is allowed",
			tag:           "User",
			isGlobalAdmin: true,
			wantAllowed:   true,
		},
		{
			// Control: non-balance-crediting transactions are unaffected by the guard,
			// so ordinary org-scoped admin actions keep working (the org-admin authz
			// grant is only narrowed for the wallet-credit path, not weakened broadly).
			name:          "org-admin non-User-tag transaction is unaffected",
			tag:           "",
			isGlobalAdmin: false,
			wantAllowed:   true,
		},
		{
			name:          "org-admin Organization-tag transaction is unaffected",
			tag:           "Organization",
			isGlobalAdmin: false,
			wantAllowed:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canCreditWalletBalance(tc.tag, tc.isGlobalAdmin)
			if got != tc.wantAllowed {
				t.Fatalf("canCreditWalletBalance(tag=%q, isGlobalAdmin=%v) = %v, want %v",
					tc.tag, tc.isGlobalAdmin, got, tc.wantAllowed)
			}
		})
	}
}
