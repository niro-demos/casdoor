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

package controllers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	beecontext "github.com/beego/beego/v2/server/web/context"
)

func callAuthorizationListing(t *testing.T, path, sessionUser string, action func(*ApiController)) (response Response, reachedDataLayer bool) {
	t.Helper()

	request := httptest.NewRequest("GET", path, nil)
	recorder := httptest.NewRecorder()
	ctx := beecontext.NewContext()
	ctx.Reset(recorder, request)
	ctx.Input.SetData("currentUserId", sessionUser)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", nil)
	func() {
		defer func() {
			if recover() != nil {
				reachedDataLayer = true
			}
		}()
		action(controller)
	}()
	if reachedDataLayer {
		return Response{}, true
	}

	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response for %s: %v (body %q)", path, err, recorder.Body.String())
	}
	return response, false
}

func TestAuthorizationListingsRejectAnonymousUserSelection(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		action func(*ApiController)
	}{
		{"objects", "/api/get-all-objects?userId=built-in/admin", (*ApiController).GetAllObjects},
		{"actions", "/api/get-all-actions?userId=built-in/admin", (*ApiController).GetAllActions},
		{"roles", "/api/get-all-roles?userId=built-in/admin", (*ApiController).GetAllRoles},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, reachedDataLayer := callAuthorizationListing(t, test.path, "", test.action)
			if reachedDataLayer {
				t.Fatal("anonymous user selection reached the authorization data layer")
			}
			if response.Status != "error" || !strings.Contains(strings.ToLower(response.Msg), "login") {
				t.Fatalf("anonymous selection returned status=%q msg=%q, want login error", response.Status, response.Msg)
			}
		})
	}
}

func TestAuthorizationListingsAllowAuthenticatedSelf(t *testing.T) {
	_, reachedDataLayer := callAuthorizationListing(
		t,
		"/api/get-all-roles?userId=built-in/admin",
		"built-in/admin",
		(*ApiController).GetAllRoles,
	)
	if !reachedDataLayer {
		t.Fatal("authenticated self request was rejected before the authorization data layer")
	}
}
