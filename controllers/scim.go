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

	// Thread the caller's organization scope through to the SCIM resource
	// handlers via the request context. An empty owner means the caller is
	// the built-in global admin (see ApiController.RequireAdmin) and is not
	// confined to a single organization; any other owner value confines every
	// SCIM Get/GetAll/Create/Patch/Replace/Delete operation to that org.
	c.Ctx.Request = c.Ctx.Request.WithContext(scim.WithOwner(c.Ctx.Request.Context(), owner))

	path := c.Ctx.Request.URL.Path
	c.Ctx.Request.URL.Path = strings.TrimPrefix(path, "/scim")
	scim.Server.ServeHTTP(c.Ctx.ResponseWriter, c.Ctx.Request)
}
