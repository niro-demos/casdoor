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

type callerOwnerContextKey struct{}

// WithCallerOwner attaches the organization the SCIM caller is confined to,
// as established by controllers.RootController.HandleScim via RequireAdmin(),
// to the request context. An empty owner means the caller is Casdoor's
// built-in global admin and is not confined to a single organization --
// mirroring RequireAdmin's own contract, where "" is returned only for that
// caller.
func WithCallerOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, callerOwnerContextKey{}, owner)
}

// callerOwner returns the organization the SCIM caller is confined to, and
// whether HandleScim actually attached a scope to the request at all.
//
// present is false only when a resource handler is reached through some path
// other than HandleScim (e.g. a test, or a future integration, that invokes
// scim.Server.ServeHTTP directly). Callers must treat that as "deny", not
// "unrestricted": an absent scope is indistinguishable from a caller nobody
// has authorized, and the previous, vulnerable behavior was exactly to treat
// "no scope information" as "every organization".
func callerOwner(r *http.Request) (owner string, present bool) {
	v := r.Context().Value(callerOwnerContextKey{})
	if v == nil {
		return "", false
	}
	owner, present = v.(string)
	return owner, present
}

// ownerAllowed reports whether a caller confined to callerOrg (as returned by
// callerOwner) may act on a resource owned by resourceOrg. The built-in
// global admin (callerOrg == "") may act on any organization's resources; a
// tenant admin may only act on resources owned by their own organization.
func ownerAllowed(callerOrg, resourceOrg string) bool {
	return callerOrg == "" || callerOrg == resourceOrg
}
