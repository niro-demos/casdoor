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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/casdoor/casdoor/object"
	elimityscim "github.com/elimity-com/scim"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "casdoor-scim-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	configPath := filepath.Join(dir, "app.conf")
	dbPath := filepath.Join(dir, "casdoor.db")
	config := fmt.Sprintf(`appname = casdoor
driverName = sqlite
dataSourceName = %s
dbName =
tableNamePrefix =
staticBaseUrl = "https://cdn.casbin.org"
isUsernameLowered = false
`, dbPath)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		panic(err)
	}

	os.Args = append(os.Args, "-config", configPath)
	object.InitFlag()
	object.InitAdapter()
	object.CreateTables()

	os.Exit(m.Run())
}

func TestUserResourceHandlerScopesReadsToRequestOwner(t *testing.T) {
	seedScimUserTestData(t)

	handler := UserResourceHandler{}
	request := requestForScimOwner("tenant-a")

	sameTenant, err := handler.Get(request, "tenant-a-user-id")
	if err != nil {
		t.Fatalf("same-tenant SCIM user read failed: %v", err)
	}
	if sameTenant.ID != "tenant-a-user-id" || sameTenant.Attributes["userName"] != "tenant-user" {
		t.Fatalf("same-tenant SCIM user = %#v", sameTenant)
	}

	crossTenant, err := handler.Get(request, "built-in-admin-id")
	if err == nil {
		t.Fatalf("cross-tenant SCIM user read returned resource %#v, want resource-not-found error", crossTenant)
	}

	page, err := handler.GetAll(request, elimityscim.ListRequestParams{StartIndex: 1, Count: 100})
	if err != nil {
		t.Fatalf("same-tenant SCIM user list failed: %v", err)
	}
	if page.TotalResults != 1 || len(page.Resources) != 1 {
		t.Fatalf("same-tenant SCIM user list returned %d total and %d resources, want exactly 1", page.TotalResults, len(page.Resources))
	}
	if page.Resources[0].ID != "tenant-a-user-id" {
		t.Fatalf("same-tenant SCIM user list included %q, want tenant-a-user-id", page.Resources[0].ID)
	}
}

func seedScimUserTestData(t *testing.T) {
	t.Helper()

	organizations := []*object.Organization{
		{Owner: "admin", Name: "built-in", HasPrivilegeConsent: true},
		{Owner: "admin", Name: "tenant-a"},
	}
	for _, organization := range organizations {
		if _, err := object.AddOrganization(organization); err != nil {
			t.Fatalf("add organization %s: %v", organization.Name, err)
		}
	}

	if _, err := object.AddApplication(&object.Application{
		Owner:        "admin",
		Name:         "app-tenant-a",
		Organization: "tenant-a",
	}); err != nil {
		t.Fatalf("add tenant application: %v", err)
	}

	users := []*object.User{
		{Owner: "built-in", Name: "admin", Id: "built-in-admin-id", DisplayName: "Admin", Email: "admin@example.com", Phone: "12345678910"},
		{Owner: "tenant-a", Name: "tenant-user", Id: "tenant-a-user-id", DisplayName: "Tenant User", Email: "tenant@example.com"},
	}
	for _, user := range users {
		if _, err := object.AddUser(user, "en"); err != nil {
			t.Fatalf("add user %s: %v", user.GetId(), err)
		}
	}
}

func requestForScimOwner(owner string) *http.Request {
	request := httptest.NewRequest("GET", "/Users", nil)
	return WithRequestOwner(request, owner)
}
