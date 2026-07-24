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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestGetResourcesScopesStandardUserToOwnMetadata(t *testing.T) {
	t.Setenv("driverName", "mysql")
	dataSourceName := os.Getenv("CASDOOR_TEST_DATA_SOURCE_NAME")
	if dataSourceName == "" {
		dataSourceName = "root:123456@tcp(127.0.0.1:3306)/"
	}
	t.Setenv("dataSourceName", dataSourceName)
	t.Setenv("dbName", "casdoor_resource_list_test")
	object.InitConfig()

	suffix := time.Now().UnixNano()
	orgName := fmt.Sprintf("niro-resource-list-test-%d", suffix)
	org := &object.Organization{
		Owner:        "admin",
		Name:         orgName,
		DisplayName:  "Niro resource list test",
		PasswordType: "plain",
		AccountItems: object.GetDefaultAccountItems(),
	}
	app := &object.Application{
		Owner:        "admin",
		Name:         fmt.Sprintf("app-%s", orgName),
		DisplayName:  "Niro resource list test",
		Organization: org.Name,
	}
	bob := &object.User{
		Owner:   org.Name,
		Name:    "bob",
		Id:      fmt.Sprintf("%s-bob", orgName),
		Type:    "normal-user",
		IsAdmin: false,
	}
	alice := &object.User{
		Owner:   org.Name,
		Name:    "alice",
		Id:      fmt.Sprintf("%s-alice", orgName),
		Type:    "normal-user",
		IsAdmin: false,
	}
	bobResource := &object.Resource{
		Owner:       org.Name,
		Name:        "/bob-resource",
		User:        bob.Name,
		FileName:    "bob.txt",
		Url:         "http://example.invalid/bob.txt",
		Description: "Bob resource",
	}
	aliceResource := &object.Resource{
		Owner:       org.Name,
		Name:        "/alice-resource",
		User:        alice.Name,
		FileName:    "alice.txt",
		Url:         "http://example.invalid/alice.txt",
		Description: "Alice resource",
	}

	mustAddOrganization(t, org)
	t.Cleanup(func() { _, _ = object.DeleteOrganization(org) })
	mustAddApplication(t, app)
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })
	mustAddUser(t, bob)
	mustAddUser(t, alice)
	mustAddResource(t, bobResource)
	t.Cleanup(func() { _, _ = object.DeleteResource(bobResource) })
	mustAddResource(t, aliceResource)
	t.Cleanup(func() { _, _ = object.DeleteResource(aliceResource) })

	tests := []struct {
		name  string
		query string
	}{
		{
			name:  "omitted user",
			query: fmt.Sprintf("/api/get-resources?owner=%s&pageSize=100", org.Name),
		},
		{
			name:  "forged user",
			query: fmt.Sprintf("/api/get-resources?owner=%s&user=alice&pageSize=100", org.Name),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources := getResourcesForTest(t, tt.query, bob.GetId())

			if !hasResourceForUser(resources, bob.Name, bobResource.Name) {
				t.Fatalf("expected Bob to receive his own resource metadata, got %#v", resources)
			}
			if hasResourceForUser(resources, alice.Name, aliceResource.Name) {
				t.Fatalf("standard user received another member's resource metadata: %#v", resources)
			}
		})
	}
}

func getResourcesForTest(t *testing.T, target string, currentUserId string) []*object.Resource {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.SetData("currentUserId", currentUserId)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "GetResources", controller)
	controller.GetResources()

	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response %q: %v", recorder.Body.String(), err)
	}
	if response.Status != "ok" {
		t.Fatalf("GetResources status = %q, msg = %q", response.Status, response.Msg)
	}

	rawResources, err := json.Marshal(response.Data)
	if err != nil {
		t.Fatal(err)
	}
	var resources []*object.Resource
	if err := json.Unmarshal(rawResources, &resources); err != nil {
		t.Fatalf("failed to decode resources %s: %v", rawResources, err)
	}

	return resources
}

func hasResourceForUser(resources []*object.Resource, user string, name string) bool {
	for _, resource := range resources {
		if resource.User == user && resource.Name == name {
			return true
		}
	}
	return false
}

func mustAddOrganization(t *testing.T, organization *object.Organization) {
	t.Helper()
	if _, err := object.AddOrganization(organization); err != nil {
		t.Fatal(err)
	}
}

func mustAddApplication(t *testing.T, application *object.Application) {
	t.Helper()
	if _, err := object.AddApplication(application); err != nil {
		t.Fatal(err)
	}
}

func mustAddUser(t *testing.T, user *object.User) {
	t.Helper()
	if _, err := object.AddUser(user, "en"); err != nil {
		t.Fatal(err)
	}
}

func mustAddResource(t *testing.T, resource *object.Resource) {
	t.Helper()
	if _, err := object.AddResource(resource); err != nil {
		t.Fatal(err)
	}
}
