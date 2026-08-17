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

	scimapi "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
)

const tenantOwnerContextKey = "casdoor.scim.owner"

func WithTenantOwner(r *http.Request, owner string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), tenantOwnerContextKey, owner))
}

func tenantOwnerFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	owner, _ := r.Context().Value(tenantOwnerContextKey).(string)
	return owner
}

func isGlobalScimAdmin(owner string) bool {
	return owner == ""
}

func forbiddenTenantOperation() error {
	return scimerrors.ScimError{
		Detail: "Operation is not permitted for the authenticated tenant.",
		Status: http.StatusForbidden,
	}
}

func resourceOwner(attrs scimapi.ResourceAttributes, extensionKey string) string {
	return getAttrJsonValue(attrs, extensionKey, "organization")
}
