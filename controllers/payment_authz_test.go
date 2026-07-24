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

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

// TestPaymentAccessOwnership pins the authorization invariant that every payment
// endpoint operating on an already-loaded payment must enforce:
//
//	A non-admin user must NOT be able to act on a payment they do not own —
//	neither a different user in the same tenant, nor any user in another tenant.
//
// The controllers GetPayment and InvoicePayment both route their decision through
// isPaymentAccessForbidden, so this single predicate test guards both the read
// path and the state-changing invoice path against the ownership guard being
// dropped from either endpoint (the regression fixed here for InvoicePayment).
func TestPaymentAccessOwnership(t *testing.T) {
	// The victim payment: owned by user "alice" in tenant "acme".
	victim := &object.Payment{Owner: "acme", User: "alice"}

	cases := []struct {
		name          string
		isAdmin       bool
		sessionUser   string // "owner/name" of the acting principal
		payment       *object.Payment
		wantForbidden bool
	}{
		{
			// The legitimate owner is allowed — proves the predicate is not a
			// blanket deny and the RED below is the invariant, not a broken setup.
			name:          "owner is allowed (control)",
			isAdmin:       false,
			sessionUser:   "acme/alice",
			payment:       victim,
			wantForbidden: false,
		},
		{
			// Cross-user, same tenant: bob (acme) must NOT reach alice's payment.
			name:          "same-tenant non-owner is forbidden",
			isAdmin:       false,
			sessionUser:   "acme/bob",
			payment:       victim,
			wantForbidden: true,
		},
		{
			// Cross-tenant: carol (globex) must NOT reach an acme payment.
			name:          "cross-tenant user is forbidden",
			isAdmin:       false,
			sessionUser:   "globex/carol",
			payment:       victim,
			wantForbidden: true,
		},
		{
			// Admins bypass the ownership check by design.
			name:          "admin is allowed",
			isAdmin:       true,
			sessionUser:   "built-in/admin",
			payment:       victim,
			wantForbidden: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := isPaymentAccessForbidden(tc.isAdmin, tc.sessionUser, tc.payment)
			if err != nil {
				t.Fatalf("isPaymentAccessForbidden returned unexpected error: %v", err)
			}
			if got != tc.wantForbidden {
				t.Fatalf("isPaymentAccessForbidden(isAdmin=%v, sessionUser=%q) = %v, want %v",
					tc.isAdmin, tc.sessionUser, got, tc.wantForbidden)
			}
		})
	}
}
