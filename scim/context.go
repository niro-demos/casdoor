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

package scim

import (
	"context"
	"net/http"
)

type callerOwnerContextKeyType struct{}

var callerOwnerContextKey = callerOwnerContextKeyType{}

// scopedCaller describes the organization boundary that controllers.HandleScim
// derived from c.RequireAdmin() for the current request. It follows the same
// convention as RequireAdmin: an empty Owner means the caller is Casdoor's
// "built-in" global administrator and is not confined to any single
// organization; any other value is the organization the caller's own account
// belongs to, and every SCIM resource handler must confine reads/writes to
// that organization.
type scopedCaller struct {
	owner         string
	isGlobalAdmin bool
}

// canAccess reports whether this caller may read/write a resource owned by
// resourceOwner: true for a global admin, or for an org-scoped admin whose
// own organization exactly matches resourceOwner.
func (sc scopedCaller) canAccess(resourceOwner string) bool {
	return sc.isGlobalAdmin || (resourceOwner != "" && resourceOwner == sc.owner)
}

// WithCallerOwner attaches the authenticated SCIM caller's organization
// scope to the request context. owner is the value controllers.RequireAdmin()
// returned for this request: "" for the built-in global admin, otherwise the
// caller's own organization.
func WithCallerOwner(r *http.Request, owner string) *http.Request {
	sc := scopedCaller{owner: owner, isGlobalAdmin: owner == ""}
	return r.WithContext(context.WithValue(r.Context(), callerOwnerContextKey, sc))
}

// callerScope returns the organization boundary attached by WithCallerOwner.
// If the context was never populated -- which should not happen in
// production, since controllers.HandleScim always calls WithCallerOwner
// before dispatching into the SCIM server -- this fails closed: not a global
// admin, and confined to an owner value that cannot match any real
// organization, so every ownership check denies access.
func callerScope(r *http.Request) scopedCaller {
	if sc, ok := r.Context().Value(callerOwnerContextKey).(scopedCaller); ok {
		return sc
	}
	return scopedCaller{owner: "\x00scim-no-caller-owner", isGlobalAdmin: false}
}
