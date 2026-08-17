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
	"path/filepath"
	"strings"
	"sync"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var publicApiAuthzSetupOnce sync.Once

const (
	publicApiAuthzTestOrg          = "security-regression-org"
	testUser         = "alice"
	testUserID       = publicApiAuthzTestOrg + "/" + testUser
	testAppOwner     = "admin"
	testAppName      = "security-regression-app"
	testSubscription = "private-subscription"
)

type controllerResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func TestPublicDetailEndpointsRejectAnonymousReads(t *testing.T) {
	setupPublicApiAuthzFixtures(t)

	tests := []struct {
		name       string
		path       string
		handler    func(*ApiController)
		forbidden  func(controllerResponse) bool
		legitimate func(t *testing.T)
	}{
		{
			name:    "user directory record",
			path:    "/api/get-user?id=" + testUserID,
			handler: (*ApiController).GetUser,
			forbidden: func(resp controllerResponse) bool {
				var user object.User
				return resp.Status == "ok" && json.Unmarshal(resp.Data, &user) == nil && user.Email == "alice.security-regression@example.test"
			},
			legitimate: func(t *testing.T) {
				resp := callApiController(t, "/api/get-user?id="+testUserID, testUserID, (*ApiController).GetUser)
				assertStatus(t, resp, "ok")
			},
		},
		{
			name:    "application configuration",
			path:    "/api/get-application?id=" + testAppOwner + "/" + testAppName,
			handler: (*ApiController).GetApplication,
			forbidden: func(resp controllerResponse) bool {
				var application object.Application
				return resp.Status == "ok" && json.Unmarshal(resp.Data, &application) == nil && application.Name == testAppName
			},
			legitimate: func(t *testing.T) {
				resp := callApiController(t, "/api/get-application?id="+testAppOwner+"/"+testAppName, "built-in/admin", (*ApiController).GetApplication)
				assertStatus(t, resp, "ok")
			},
		},
		{
			name:    "authorization objects",
			path:    "/api/get-all-objects?userId=" + testUserID,
			handler: (*ApiController).GetAllObjects,
			forbidden: func(resp controllerResponse) bool {
				var objects []string
				return resp.Status == "ok" && json.Unmarshal(resp.Data, &objects) == nil && containsString(objects, "private-object")
			},
			legitimate: func(t *testing.T) {
				resp := callApiController(t, "/api/get-all-objects", testUserID, (*ApiController).GetAllObjects)
				assertStringListContains(t, resp, "private-object")
			},
		},
		{
			name:    "authorization actions",
			path:    "/api/get-all-actions?userId=" + testUserID,
			handler: (*ApiController).GetAllActions,
			forbidden: func(resp controllerResponse) bool {
				var actions []string
				return resp.Status == "ok" && json.Unmarshal(resp.Data, &actions) == nil && containsString(actions, "private-action")
			},
			legitimate: func(t *testing.T) {
				resp := callApiController(t, "/api/get-all-actions", testUserID, (*ApiController).GetAllActions)
				assertStringListContains(t, resp, "private-action")
			},
		},
		{
			name:    "subscription detail",
			path:    "/api/get-subscription?id=" + publicApiAuthzTestOrg + "/" + testSubscription,
			handler: (*ApiController).GetSubscription,
			forbidden: func(resp controllerResponse) bool {
				var subscription object.Subscription
				return resp.Status == "ok" && json.Unmarshal(resp.Data, &subscription) == nil && subscription.Name == testSubscription
			},
			legitimate: func(t *testing.T) {
				resp := callApiController(t, "/api/get-subscription?id="+publicApiAuthzTestOrg+"/"+testSubscription, testUserID, (*ApiController).GetSubscription)
				assertStatus(t, resp, "ok")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.legitimate(t)

			resp := callApiController(t, tt.path, "", tt.handler)
			if tt.forbidden(resp) {
				t.Fatalf("anonymous request exposed %s: status=%q data=%s", tt.name, resp.Status, string(resp.Data))
			}
		})
	}
}

func setupPublicApiAuthzFixtures(t *testing.T) {
	t.Helper()

	var setupErr error
	publicApiAuthzSetupOnce.Do(func() {
		t.Setenv("driverName", "sqlite")
		t.Setenv("dataSourceName", "file:"+filepath.Join(t.TempDir(), "casdoor-security-regression.db"))
		t.Setenv("dbName", "")
		object.SetCreateDatabaseForTesting(false)
		object.InitConfig()
		object.InitDb()

		var ok bool
		ok, setupErr = object.AddOrganization(&object.Organization{
			Owner:           "admin",
			Name:            publicApiAuthzTestOrg,
			DisplayName:     "Security Regression Org",
			CreatedTime:     util.GetCurrentTime(),
			PasswordType:    "plain",
			AccountItems:    object.GetDefaultAccountItems(),
			IsProfilePublic: true,
		})
		mustAdd(t, ok, setupErr)
		ok, setupErr = object.AddApplication(&object.Application{
			Owner:          testAppOwner,
			Name:           testAppName,
			DisplayName:    "Security Regression App",
			CreatedTime:    util.GetCurrentTime(),
			Organization:   publicApiAuthzTestOrg,
			EnablePassword: true,
			EnableSignUp:   true,
			ClientId:       "security-regression-client",
			ClientSecret:   "security-regression-secret",
		})
		mustAdd(t, ok, setupErr)
		ok, setupErr = object.AddUser(&object.User{
			Owner:             publicApiAuthzTestOrg,
			Name:              testUser,
			CreatedTime:       util.GetCurrentTime(),
			Type:              "normal-user",
			Password:          "regression-password",
			DisplayName:       "Alice Regression",
			Email:             "alice.security-regression@example.test",
			Phone:             "15555550123",
			Affiliation:       "Security Regression",
			SignupApplication: testAppName,
			CreatedIp:         "127.0.0.1",
			Properties:        map[string]string{},
		}, "en")
		mustAdd(t, ok, setupErr)
		ok, setupErr = object.AddSubscription(&object.Subscription{
			Owner:       publicApiAuthzTestOrg,
			Name:        testSubscription,
			DisplayName: "Private Subscription",
			CreatedTime: util.GetCurrentTime(),
			Description: "private test subscription",
			User:        testUser,
			Pricing:     "private-pricing",
			Plan:        "private-plan",
			State:       object.SubStateActive,
		})
		mustAdd(t, ok, setupErr)
		ok, setupErr = object.AddPermission(&object.Permission{
			Owner:        "built-in",
			Name:         "security-regression-permission",
			CreatedTime:  util.GetCurrentTime(),
			DisplayName:  "Security Regression Permission",
			Users:        []string{testUserID},
			Groups:       []string{},
			Roles:        []string{},
			Domains:      []string{},
			Model:        "built-in/user-model-built-in",
			Adapter:      "",
			ResourceType: "Application",
			Resources:    []string{"private-object"},
			Actions:      []string{"private-action"},
			Effect:       "Allow",
			IsEnabled:    true,
			Submitter:    "admin",
			Approver:     "admin",
			State:        "Approved",
		})
		mustAdd(t, ok, setupErr)
	})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
}

func callApiController(t *testing.T, target string, sessionUser string, handler func(*ApiController)) controllerResponse {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Accept-Language", "en")
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, request)
	ctx.Input.SetData("currentUserId", sessionUser)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", controller)
	handler(controller)

	var resp controllerResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response was not JSON: %v: %s", err, strings.TrimSpace(recorder.Body.String()))
	}
	return resp
}

func assertStatus(t *testing.T, resp controllerResponse, want string) {
	t.Helper()
	if resp.Status != want {
		t.Fatalf("status = %q, want %q, msg=%q data=%s", resp.Status, want, resp.Msg, string(resp.Data))
	}
}

func assertStringListContains(t *testing.T, resp controllerResponse, want string) {
	t.Helper()
	assertStatus(t, resp, "ok")

	var items []string
	if err := json.Unmarshal(resp.Data, &items); err != nil {
		t.Fatalf("data was not a string list: %v: %s", err, string(resp.Data))
	}
	if !containsString(items, want) {
		t.Fatalf("data = %#v, want item %q", items, want)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func mustAdd(t *testing.T, ok bool, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("fixture insert did not affect any rows")
	}
}
