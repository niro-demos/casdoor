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

	"github.com/elimity-com/scim/errors"
)

type contextKey int

// ownerContextKey is the request-context key HandleScim uses to carry the
// caller's organization scope (as resolved by ApiController.RequireAdmin)
// into every SCIM resource handler.
const ownerContextKey contextKey = iota

// WithOwner returns a copy of ctx carrying the SCIM caller's organization
// scope. An empty owner means the caller is the platform's built-in global
// admin and is not confined to a single organization - this mirrors the
// (owner, ok) contract of ApiController.RequireAdmin.
func WithOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, ownerContextKey, owner)
}

// ownerFromRequest returns the organization the SCIM caller is confined to
// and whether that confinement applies. scoped == false means the caller is
// the built-in global admin (or no scope was set on the request context, e.g.
// in tests that call handler functions directly) and resource handlers must
// not filter by organization.
func ownerFromRequest(r *http.Request) (owner string, scoped bool) {
	v, _ := r.Context().Value(ownerContextKey).(string)
	return v, v != ""
}

// scimErrorForbidden returns a 403 SCIM error for a caller whose organization
// scope does not permit the attempted operation.
func scimErrorForbidden(detail string) errors.ScimError {
	return errors.ScimError{
		Status: http.StatusForbidden,
		Detail: detail,
	}
}

// checkOwnerScope reports whether a resource owned by resourceOwner is
// visible to a caller confined to callerOwner. scoped == false (the built-in
// global admin) always sees every organization.
func checkOwnerScope(resourceOwner, callerOwner string, scoped bool) bool {
	return !scoped || resourceOwner == callerOwner
}
