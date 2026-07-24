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
	"net/http"
	"net/http/httptest"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestGetGlobalUsersRequiresGlobalAdmin(t *testing.T) {
	object.InitConfig()
	seedGlobalUsersAuthzTestData(t)

	orgAdminResponse := callGetGlobalUsers(t, "niro-test/org-admin")
	if orgAdminResponse.Status != "error" {
		t.Fatalf("organization admin retrieved global users: status=%q data=%v", orgAdminResponse.Status, orgAdminResponse.Data)
	}
	if orgAdminResponse.Msg != "Unauthorized operation" {
		t.Fatalf("organization admin denial msg = %q, want %q", orgAdminResponse.Msg, "Unauthorized operation")
	}

	globalAdminResponse := callGetGlobalUsers(t, "built-in/admin")
	if globalAdminResponse.Status != "ok" {
		t.Fatalf("global admin listing status=%q msg=%q, want ok", globalAdminResponse.Status, globalAdminResponse.Msg)
	}
	if !responseContainsUser(globalAdminResponse, "built-in", "admin") {
		t.Fatalf("global admin listing did not include built-in/admin: %#v", globalAdminResponse.Data)
	}
}

func seedGlobalUsersAuthzTestData(t *testing.T) {
	t.Helper()

	_, _ = object.AddOrganization(&object.Organization{Owner: "admin", Name: "built-in", HasPrivilegeConsent: true})
	_, _ = object.AddOrganization(&object.Organization{Owner: "admin", Name: "niro-test"})
	_, _ = object.AddApplication(&object.Application{Owner: "admin", Name: "app-niro-test", Organization: "niro-test"})
	_, err := object.AddUsers([]*object.User{
		{Owner: "built-in", Name: "admin", Email: "admin@example.com"},
		{Owner: "niro-test", Name: "org-admin", Email: "org-admin@example.com", IsAdmin: true},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func callGetGlobalUsers(t *testing.T, currentUserId string) *Response {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/api/get-global-users?owner=niro-test", nil)
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, request)
	ctx.Input.SetData("currentUserId", currentUserId)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "GetGlobalUsers", controller)
	controller.GetGlobalUsers()

	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v: %s", err, recorder.Body.String())
	}
	return &response
}

func responseContainsUser(response *Response, owner string, name string) bool {
	users, ok := response.Data.([]interface{})
	if !ok {
		return false
	}

	for _, rawUser := range users {
		user, ok := rawUser.(map[string]interface{})
		if !ok {
			continue
		}
		if user["owner"] == owner && user["name"] == name {
			return true
		}
	}
	return false
}
