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

import "github.com/casdoor/casdoor/util"

// canReadTenantScope encodes the tenant-scoping invariant shared by the
// tenant-scoped read endpoints (e.g. GET /api/get-resources,
// GET /api/get-all-objects / -actions / -roles).
//
// A caller may read data scoped to requestedOwner only when:
//   - it is a global (cross-org) admin, OR
//   - it belongs to that same organization (its own owner == requestedOwner).
//
// An anonymous caller (empty callerOwner) is never allowed. A caller that
// requests no owner at all (empty requestedOwner) is out of scope for this
// check and is handled by the caller (typically resolved to the caller's own
// identity before this function is consulted).
//
// This is deliberately a pure function of the caller's established identity and
// the requested owner, with no HTTP or DB coupling, so the security invariant
// can be regression-tested directly. The route-level Casbin policy is a
// cooperating layer; this handler-level check is the load-bearing guarantee and
// holds regardless of how permissive that policy is.
func canReadTenantScope(callerOwner string, callerIsGlobalAdmin bool, requestedOwner string) bool {
	// A global admin may read any organization's scope.
	if callerIsGlobalAdmin {
		return true
	}

	// Anonymous / unauthenticated callers can never read a tenant scope.
	if callerOwner == "" {
		return false
	}

	// Otherwise the caller may only read its own organization's scope.
	return requestedOwner != "" && callerOwner == requestedOwner
}

// requireTenantScope enforces canReadTenantScope for the current request against
// a client-supplied requestedOwner. It resolves the caller's identity from the
// session, and on any failure (not signed in, or cross-tenant without global
// admin) it writes an "Unauthorized operation" error response and returns false,
// mirroring how the sibling tenant-scoped endpoints reject.
//
// On success it returns true and the request may proceed. A returned false means
// the response has already been written and the handler must return immediately.
func (c *ApiController) requireTenantScope(requestedOwner string) bool {
	// Global (cross-org) admins, and internal app subjects, may read any owner.
	isGlobalAdmin, user := c.isGlobalAdmin()
	if isGlobalAdmin {
		return true
	}

	// Anyone else must be a signed-in user resolvable to an organization.
	if user == nil {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return false
	}

	if !canReadTenantScope(user.Owner, false, requestedOwner) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return false
	}

	return true
}

// requireUserScope enforces the tenant-scoping invariant for endpoints that take
// a target user as a `userId` query parameter of the form "owner/name"
// (GET /api/get-all-objects / -actions / -roles). It derives the owner from the
// target userId and requires the caller to be a global admin, or a member of
// that same organization (which includes the user reading its own grants).
//
// A malformed userId, an unauthenticated caller, or a cross-tenant caller is
// rejected with "Unauthorized operation"; on rejection the response is already
// written and the caller returns false.
func (c *ApiController) requireUserScope(userId string) bool {
	targetOwner, _, err := util.GetOwnerAndNameFromIdWithError(userId)
	if err != nil {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return false
	}

	return c.requireTenantScope(targetOwner)
}
