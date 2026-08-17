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
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestRefreshEnginesRequiresGlobalAdmin(t *testing.T) {
	setupRefreshEnginesTestData(t)

	tests := []struct {
		name        string
		currentUser string
		wantStatus  string
		wantMsg     string
	}{
		{
			name:        "tenant admin is rejected before request validation",
			currentUser: "niro-alpha/admin",
			wantStatus:  "error",
			wantMsg:     "Unauthorized operation",
		},
		{
			name:        "global app admin passes authorization",
			currentUser: "app/app-built-in",
			wantStatus:  "error",
			wantMsg:     "invalid identifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, recorder := newRefreshEnginesController(tt.currentUser)

			controller.RefreshEngines()

			if recorder.Code != http.StatusOK {
				t.Fatalf("HTTP status = %d, want %d", recorder.Code, http.StatusOK)
			}

			var response Response
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v; body=%s", err, recorder.Body.String())
			}

			if response.Status != tt.wantStatus {
				t.Fatalf("response status = %q, want %q; body=%s", response.Status, tt.wantStatus, recorder.Body.String())
			}
			if !strings.Contains(response.Msg, tt.wantMsg) {
				t.Fatalf("response msg = %q, want it to contain %q; body=%s", response.Msg, tt.wantMsg, recorder.Body.String())
			}
		})
	}
}

func setupRefreshEnginesTestData(t *testing.T) {
	t.Helper()

	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", filepath.Join(t.TempDir(), "casdoor-test.db"))
	t.Setenv("dbName", "")
	t.Setenv("isDemoMode", "false")
	object.SetCreateDatabaseForTesting(false)

	object.InitConfig()

	mustAddOrganization(t, &object.Organization{
		Owner:       "admin",
		Name:        "niro-alpha",
		DisplayName: "Niro Alpha",
	})
	mustAddApplication(t, &object.Application{
		Owner:        "admin",
		Name:         "app-niro-alpha",
		DisplayName:  "Niro Alpha",
		Organization: "niro-alpha",
	})
	mustAddUser(t, &object.User{
		Owner:             "niro-alpha",
		Name:              "admin",
		DisplayName:       "Tenant Admin",
		Password:          "test-password",
		SignupApplication: "app-niro-alpha",
		IsAdmin:           true,
	})
}

func mustAddOrganization(t *testing.T, organization *object.Organization) {
	t.Helper()

	if _, err := object.AddOrganization(organization); err != nil {
		t.Fatalf("add organization: %v", err)
	}
}

func mustAddApplication(t *testing.T, application *object.Application) {
	t.Helper()

	if _, err := object.AddApplication(application); err != nil {
		t.Fatalf("add application: %v", err)
	}
}

func mustAddUser(t *testing.T, user *object.User) {
	t.Helper()

	if _, err := object.AddUser(user, "en"); err != nil {
		t.Fatalf("add user: %v", err)
	}
}

func newRefreshEnginesController(currentUser string) (*ApiController, *httptest.ResponseRecorder) {
	request := httptest.NewRequest(http.MethodPost, "/api/refresh-engines", nil)
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, request)
	ctx.Input.SetData("currentUserId", currentUser)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "RefreshEngines", controller)

	return controller, recorder
}
