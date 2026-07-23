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
	"testing"

	"github.com/casdoor/casdoor/object"
)

// TestIsOrderOwnerAuthorized asserts the invariant behind PlaceOrder:
// a user must not be able to place or pay for orders inside another
// organization's commerce scope (nor consume its coupon inventory) unless they
// belong to that org or are an admin.
//
// Cross-tenant case (the bug: TC-7C271177) is the RED assertion; the same-org
// and admin cases are the paired positive controls that prove the check is
// specific and not a blanket denial.
func TestIsOrderOwnerAuthorized(t *testing.T) {
	tests := []struct {
		name      string
		owner     string // target org taken from the ?owner= query param
		callerOrg string // the caller's own organization
		isAdmin   bool
		want      bool
	}{
		{
			name:      "cross-tenant non-admin is rejected",
			owner:     "org-alpha",
			callerOrg: "org-beta",
			isAdmin:   false,
			want:      false,
		},
		{
			name:      "same-org non-admin is allowed (positive control)",
			owner:     "org-beta",
			callerOrg: "org-beta",
			isAdmin:   false,
			want:      true,
		},
		{
			name:      "admin may target any org (positive control)",
			owner:     "org-alpha",
			callerOrg: "org-beta",
			isAdmin:   true,
			want:      true,
		},
		{
			name:      "empty owner for a non-admin is rejected",
			owner:     "",
			callerOrg: "org-beta",
			isAdmin:   false,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isOrderOwnerAuthorized(tt.owner, tt.callerOrg, tt.isAdmin)
			if got != tt.want {
				t.Fatalf("isOrderOwnerAuthorized(owner=%q, callerOrg=%q, isAdmin=%v) = %v, want %v",
					tt.owner, tt.callerOrg, tt.isAdmin, got, tt.want)
			}
		})
	}
}

// TestIsPaymentAccessAuthorized asserts the invariant behind InvoicePayment:
// a user must not be able to generate or fetch the invoice for another user's /
// another tenant's payment (TC-D314B5AC). Mirrors the gate already enforced by
// GetPayment.
//
// The cross-tenant case is the RED assertion; the owner and admin cases are the
// paired positive controls proving the gate is specific, not a blanket denial.
func TestIsPaymentAccessAuthorized(t *testing.T) {
	alphaPayment := &object.Payment{Owner: "org-alpha", User: "alpha-user"}

	tests := []struct {
		name        string
		payment     *object.Payment
		sessionUser string // "owner/name" id of the caller
		isAdmin     bool
		want        bool
		wantErr     bool
	}{
		{
			name:        "cross-tenant non-admin is rejected",
			payment:     alphaPayment,
			sessionUser: "org-beta/beta-user",
			isAdmin:     false,
			want:        false,
		},
		{
			name:        "same-tenant different user non-admin is rejected",
			payment:     alphaPayment,
			sessionUser: "org-alpha/other-user",
			isAdmin:     false,
			want:        false,
		},
		{
			name:        "payment owner non-admin is allowed (positive control)",
			payment:     alphaPayment,
			sessionUser: "org-alpha/alpha-user",
			isAdmin:     false,
			want:        true,
		},
		{
			name:        "admin may access any tenant's payment (positive control)",
			payment:     alphaPayment,
			sessionUser: "org-beta/beta-user",
			isAdmin:     true,
			want:        true,
		},
		{
			name:        "malformed session user id is rejected with error",
			payment:     alphaPayment,
			sessionUser: "not-an-id",
			isAdmin:     false,
			want:        false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isPaymentAccessAuthorized(tt.payment, tt.sessionUser, tt.isAdmin)
			if tt.wantErr && err == nil {
				t.Fatalf("isPaymentAccessAuthorized(sessionUser=%q) expected an error, got nil", tt.sessionUser)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("isPaymentAccessAuthorized(sessionUser=%q) unexpected error: %v", tt.sessionUser, err)
			}
			if got != tt.want {
				t.Fatalf("isPaymentAccessAuthorized(payment=%+v, sessionUser=%q, isAdmin=%v) = %v, want %v",
					tt.payment, tt.sessionUser, tt.isAdmin, got, tt.want)
			}
		})
	}
}
