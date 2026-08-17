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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	_ "unsafe"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/casdoor/casdoor/object"
	scimapi "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
)

//go:linkname objectOrmer github.com/casdoor/casdoor/object.ormer
var objectOrmer *object.Ormer

//go:linkname objectCreateDatabase github.com/casdoor/casdoor/object.createDatabase
var objectCreateDatabase bool

//go:linkname objectUserEnforcer github.com/casdoor/casdoor/object.userEnforcer
var objectUserEnforcer *object.UserGroupEnforcer

const testTenantOwnerContextKey = "casdoor.scim.owner"

func TestUserResourceHandlerHonorsTenantContext(t *testing.T) {
	setupTenantContextTestDb(t)
	seedUser(t, "niro-alpha", "alpha-admin", "alpha-admin-id")
	seedUser(t, "niro-beta", "beta-alice", "beta-alice-id")

	req := tenantRequest("niro-alpha")
	page, err := UserResourceHandler{}.GetAll(req, scimapi.ListRequestParams{StartIndex: 1, Count: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range page.Resources {
		if resource.ID == "beta-alice-id" {
			t.Errorf("tenant-scoped SCIM user list leaked beta user: %#v", resource)
		}
	}

	if _, err := (UserResourceHandler{}).Get(req, "beta-alice-id"); !isScimNotFound(err) {
		t.Errorf("tenant alpha read beta user error = %v, want SCIM not found", err)
	}

	attrs := userAttrs("cross-user", "niro-beta")
	if _, err := (UserResourceHandler{}).Create(req, attrs); !isScimForbidden(err) {
		t.Errorf("tenant alpha cross-tenant user create error = %v, want SCIM forbidden", err)
	}

	betaReq := tenantRequest("niro-beta")
	if _, err := (UserResourceHandler{}).Get(betaReq, "beta-alice-id"); err != nil {
		t.Errorf("same-tenant beta user read failed: %v", err)
	}

	if err := (UserResourceHandler{}).Delete(req, "beta-alice-id"); !isScimForbidden(err) {
		t.Errorf("tenant alpha cross-tenant user delete error = %v, want SCIM forbidden", err)
	}
}

func TestGroupResourceHandlerHonorsTenantContext(t *testing.T) {
	setupTenantContextTestDb(t)
	seedGroup(t, "niro-alpha", "alpha-group")
	seedGroup(t, "niro-beta", "beta-group")

	req := tenantRequest("niro-alpha")
	page, err := GroupResourceHandler{}.GetAll(req, scimapi.ListRequestParams{StartIndex: 1, Count: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range page.Resources {
		if resource.ID == "niro-beta/beta-group" {
			t.Errorf("tenant-scoped SCIM group list leaked beta group: %#v", resource)
		}
	}

	if _, err := (GroupResourceHandler{}).Get(req, "niro-beta/beta-group"); !isScimNotFound(err) {
		t.Errorf("tenant alpha read beta group error = %v, want SCIM not found", err)
	}

	if _, err := (GroupResourceHandler{}).Create(req, groupAttrs("cross-group", "niro-beta")); !isScimForbidden(err) {
		t.Errorf("tenant alpha cross-tenant group create error = %v, want SCIM forbidden", err)
	}

	betaReq := tenantRequest("niro-beta")
	if _, err := (GroupResourceHandler{}).Get(betaReq, "niro-beta/beta-group"); err != nil {
		t.Errorf("same-tenant beta group read failed: %v", err)
	}

	if err := (GroupResourceHandler{}).Delete(req, "niro-beta/beta-group"); !isScimForbidden(err) {
		t.Errorf("tenant alpha cross-tenant group delete error = %v, want SCIM forbidden", err)
	}
}

func setupTenantContextTestDb(t *testing.T) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "casdoor-scim-test.db")
	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", dbPath)
	t.Setenv("dbName", "")
	t.Setenv("showSql", "false")

	adapter, err := object.NewAdapter("sqlite", dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	objectOrmer = adapter
	objectCreateDatabase = false
	object.CreateTables()
	objectUserEnforcer = newTestUserGroupEnforcer(t)

	seedOrganization(t, "niro-alpha")
	seedOrganization(t, "niro-beta")
	seedApplication(t, "app-niro-alpha", "niro-alpha")
	seedApplication(t, "app-niro-beta", "niro-beta")
}

func newTestUserGroupEnforcer(t *testing.T) *object.UserGroupEnforcer {
	t.Helper()

	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := casbin.NewSyncedEnforcer(m, stringadapter.NewAdapter("g, test-user, test-group"))
	if err != nil {
		t.Fatal(err)
	}
	return object.NewUserGroupEnforcer(enforcer)
}

func seedOrganization(t *testing.T, name string) {
	t.Helper()

	_, err := object.AddOrganization(&object.Organization{
		Owner:        "admin",
		Name:         name,
		CreatedTime:  time.Now().UTC().Format(time.RFC3339),
		DisplayName:  name,
		PasswordType: "plain",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func seedApplication(t *testing.T, name string, organization string) {
	t.Helper()

	_, err := object.AddApplication(&object.Application{
		Owner:          "admin",
		Name:           name,
		CreatedTime:    time.Now().UTC().Format(time.RFC3339),
		DisplayName:    name,
		Organization:   organization,
		EnablePassword: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func seedUser(t *testing.T, owner string, name string, id string) {
	t.Helper()

	_, err := object.AddUser(&object.User{
		Owner:       owner,
		Name:        name,
		Id:          id,
		DisplayName: fmt.Sprintf("%s %s", owner, name),
		Email:       fmt.Sprintf("%s@example.test", name),
		Password:    "123456",
	}, "en")
	if err != nil {
		t.Fatal(err)
	}
}

func seedGroup(t *testing.T, owner string, name string) {
	t.Helper()

	_, err := object.AddGroup(&object.Group{
		Owner:       owner,
		Name:        name,
		DisplayName: name,
		CreatedTime: time.Now().UTC().Format(time.RFC3339),
		UpdatedTime: time.Now().UTC().Format(time.RFC3339),
		IsTopGroup:  true,
		IsEnabled:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func tenantRequest(owner string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/scim", nil)
	return req.WithContext(context.WithValue(req.Context(), testTenantOwnerContextKey, owner))
}

func userAttrs(name string, owner string) scimapi.ResourceAttributes {
	return scimapi.ResourceAttributes{
		"userName":    name,
		"password":    "123456",
		"displayName": name,
		"name": map[string]interface{}{
			"givenName":  name,
			"familyName": "test",
		},
		"emails": []interface{}{
			map[string]interface{}{"value": fmt.Sprintf("%s@example.test", name)},
		},
		UserExtensionKey: map[string]interface{}{
			"organization": owner,
		},
	}
}

func groupAttrs(displayName string, owner string) scimapi.ResourceAttributes {
	return scimapi.ResourceAttributes{
		"displayName": displayName,
		GroupExtensionKey: map[string]interface{}{
			"organization": owner,
		},
	}
}

func isScimForbidden(err error) bool {
	scimErr, ok := err.(scimerrors.ScimError)
	return ok && scimErr.Status == http.StatusForbidden
}

func isScimNotFound(err error) bool {
	scimErr, ok := err.(scimerrors.ScimError)
	return ok && scimErr.Status == http.StatusNotFound
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
