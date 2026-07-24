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

package object

// CanReadOwnedRecord decides whether a caller is allowed to read a single
// tenant-owned record fetched by id.
//
// It centralizes the ownership/tenant check that the billing "get by id"
// endpoints (get-pricing, get-plan, get-subscription, get-payment, ...) must
// apply so that a non-admin caller in one tenant cannot read another tenant's
// record simply by supplying its id.
//
// Semantics (mirrors the existing controllers/payment.go GetPayment check):
//   - Admins (global admins and org admins) may read any record.
//   - A non-admin may read a record only when the record's owner matches the
//     caller's own organization. For records that additionally identify a
//     specific user (e.g. a subscription's User field), the record's user must
//     also match the caller's own name; pass recordUser == "" for record types
//     that are owned at the tenant level only (pricing, plan).
//
// It is intentionally a pure function of its inputs (no DB, no request context)
// so the security invariant can be unit-tested directly.
func CanReadOwnedRecord(isAdmin bool, sessionUserOwner, sessionUserName, recordOwner, recordUser string) bool {
	if isAdmin {
		return true
	}

	if recordOwner != sessionUserOwner {
		return false
	}

	if recordUser != "" && recordUser != sessionUserName {
		return false
	}

	return true
}
