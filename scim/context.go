// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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

// contextKey is an unexported type so values stored under it can't collide
// with keys set by other packages using the same underlying string.
type contextKey string

// OwnerContextKey is the request-context key controllers.HandleScim uses to
// carry the caller's organization into the SCIM resource handlers: "" for
// the unrestricted built-in global admin, or the caller's own organization
// name for an org-scoped admin (see controllers.RequireAdmin).
const OwnerContextKey contextKey = "casdoorScimCallerOwner"
