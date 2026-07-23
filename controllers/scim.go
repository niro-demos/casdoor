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

package controllers

import (
	"strings"

	"github.com/casdoor/casdoor/scim"
)

func (c *RootController) HandleScim() {
	owner, ok := c.RequireAdmin()
	if !ok {
		return
	}

	// Thread the caller's organization ("owner") into the SCIM layer so every
	// resource handler can enforce tenant isolation. RequireAdmin returns the
	// empty string for a global/built-in admin (allowed across all tenants) and
	// the admin's own organization otherwise. Discarding this value here is what
	// previously let an org-scoped admin read/modify/delete users in any tenant.
	req := c.Ctx.Request
	req = req.WithContext(scim.WithCallerOwner(req.Context(), owner))

	path := req.URL.Path
	req.URL.Path = strings.TrimPrefix(path, "/scim")
	scim.Server.ServeHTTP(c.Ctx.ResponseWriter, req)
}
