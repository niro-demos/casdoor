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

type contextKey int

const orgScopeContextKey contextKey = iota

// WithOrgScope returns a copy of ctx carrying the caller's organization scope
// for a SCIM request. An empty owner means the caller is a global admin with
// instance-wide access; any other value confines the request to that
// organization. Callers (controllers.HandleScim) must set this before
// dispatching to Server.ServeHTTP so every resource handler can enforce it.
func WithOrgScope(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, orgScopeContextKey, owner)
}

// OrgScopeFromContext returns the organization scope carried on r's context,
// as set by WithOrgScope. "" means instance-wide (global admin) access.
func OrgScopeFromContext(r *http.Request) string {
	if r == nil {
		return ""
	}
	scope, _ := r.Context().Value(orgScopeContextKey).(string)
	return scope
}
