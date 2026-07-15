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
	// RequireAdmin returns the caller's organization: "" for a global admin
	// (instance-wide access), or the caller's own org for an org-scoped admin.
	// That scope must be threaded through to every SCIM resource handler so an
	// org-scoped admin can never read or write another organization's data.
	owner, ok := c.RequireAdmin()
	if !ok {
		return
	}

	path := c.Ctx.Request.URL.Path
	c.Ctx.Request.URL.Path = strings.TrimPrefix(path, "/scim")
	req := c.Ctx.Request.WithContext(scim.WithOrgScope(c.Ctx.Request.Context(), owner))
	scim.Server.ServeHTTP(c.Ctx.ResponseWriter, req)
}
