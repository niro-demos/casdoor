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

package routers

import (
	"net/http"

	"github.com/beego/beego/v2/server/web/context"
)

const sessionCookieName = "casdoor_session_id"

func SecurityTransportFilter(ctx *context.Context) {
	if ctx.Input.IsSecure() {
		return
	}
	if !isAuthSessionRequest(ctx.Request) {
		return
	}

	ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
	ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
	_, _ = ctx.ResponseWriter.Write([]byte(`{"status":"error","msg":"authentication requires HTTPS"}`))
	ctx.ResponseWriter.Started = true
}

func isAuthSessionRequest(req *http.Request) bool {
	if req.Method == http.MethodPost && req.URL.Path == "/api/login" {
		return true
	}
	_, err := req.Cookie(sessionCookieName)
	return err == nil
}
