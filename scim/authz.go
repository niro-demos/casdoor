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

// callerOwnerContextKey is the request-context key under which HandleScim stores
// the organization ("owner") of the admin who authenticated to the SCIM API.
//
// The value is the caller's own organization for an org-scoped admin (e.g.
// "org-alpha"), and the empty string for a global/built-in admin who is allowed
// to operate across every tenant.
type callerOwnerContextKeyType struct{}

var callerOwnerContextKey = callerOwnerContextKeyType{}

// WithCallerOwner returns a copy of ctx carrying the SCIM caller's organization
// so the resource handlers can enforce tenant isolation.
func WithCallerOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, callerOwnerContextKey, owner)
}

// callerOwnerFromRequest extracts the caller's organization previously stored by
// HandleScim. The second return value reports whether a caller owner was present
// on the request at all; a missing value must be treated as "no tenant context"
// and therefore denied, never as "global admin".
func callerOwnerFromRequest(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	owner, ok := r.Context().Value(callerOwnerContextKey).(string)
	return owner, ok
}

// callerCanAccessOwner decides whether a SCIM caller scoped to callerOwner may
// read or mutate a resource owned by resourceOwner.
//
//   - A global/built-in admin (callerOwner == "") may access every tenant.
//   - An org-scoped admin may access only resources in its own organization.
func callerCanAccessOwner(callerOwner, resourceOwner string) bool {
	if callerOwner == "" {
		// Global/built-in admin: no tenant restriction.
		return true
	}
	return callerOwner == resourceOwner
}
