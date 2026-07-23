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
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// isOrderOwnerAuthorized reports whether a caller whose own organization is
// callerOrg (and whose admin status is isAdmin) may place/pay for an order
// inside the target organization scope `owner`.
//
// The commerce endpoints take `owner` straight from the caller-supplied query
// string and use it to select which tenant's catalog, coupons, and order ledger
// are mutated. A non-admin caller must therefore only be allowed to transact in
// their own organization; anything else is a cross-tenant write. This mirrors
// the ownership pattern already applied to the sibling `userName` parameter in
// PlaceOrder and to `PayOrder`/`CancelOrder`.
func isOrderOwnerAuthorized(owner string, callerOrg string, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	// A non-admin may only transact inside their own organization. An empty
	// owner is not a valid tenant scope for a non-admin caller.
	return owner != "" && owner == callerOrg
}

// isPaymentAccessAuthorized reports whether the session user (identified by the
// "owner/name" id sessionUser, with admin status isAdmin) may act on the given
// payment — reading it, or generating its invoice.
//
// This mirrors the ownership/admin gate already present in GetPayment,
// GetUserPayments, and GetPayments: an admin may act on any payment, while a
// non-admin may act only on a payment whose Owner and User match their own.
func isPaymentAccessAuthorized(payment *object.Payment, sessionUser string, isAdmin bool) (bool, error) {
	if isAdmin {
		return true, nil
	}

	sessionUserOwner, sessionUserName, err := util.GetOwnerAndNameFromIdWithError(sessionUser)
	if err != nil {
		return false, err
	}

	if payment != nil && (payment.Owner != sessionUserOwner || payment.User != sessionUserName) {
		return false, nil
	}

	return true, nil
}
