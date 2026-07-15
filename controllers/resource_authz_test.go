// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// callGetResources drives (*ApiController).GetResources() in-process, the
// same way a live HTTP request does, but without a real socket or session
// cookie: GetSessionUsername() reads ctx.Input.GetData("currentUserId")
// first, which is exactly what routers.ApiFilter stashes there for a real
// request after resolving the session. Setting it directly here exercises
// the real, unmodified controller method end to end.
func callGetResources(t *testing.T, signedInUserId, rawQuery string) (status string, msg string, body []byte) {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/api/get-resources?"+rawQuery, nil)
	w := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(w, r)
	if signedInUserId != "" {
		ctx.Input.SetData("currentUserId", signedInUserId)
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetResources", nil)
	c.GetResources()

	body = w.Body.Bytes()
	var parsed Response
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("GetResources did not return valid JSON: %v (body=%s)", err, body)
	}
	return parsed.Status, parsed.Msg, body
}

// TestGetResourcesEnforcesCallerOwnership is a regression test for
// TC-A113ABC1: GetResources() authorized every caller via IsOrgAdmin(),
// which only looks at the caller's own IsAdmin flag and never compares the
// request's owner/user query params against the caller's own identity. That
// let any authenticated user list another organization's resource records
// (private file metadata) just by naming that org/user in the query string.
//
// Fixtures are created directly through the object package (this package's
// own test factories), not read from Niro's ephemeral harness seed data, so
// this test is self-contained and reproducible against any freshly booted
// instance.
func TestGetResourcesEnforcesCallerOwnership(t *testing.T) {
	object.InitConfig()
	object.InitUserManager()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	testOrg := "niro-regress-org-" + suffix
	testApp := "niro-regress-app-" + suffix
	standardUserName := "niro-regress-std-" + suffix
	orgAdminUserName := "niro-regress-orgadmin-" + suffix
	victimResourceName := "niro-regress-victim-" + suffix

	organization := &object.Organization{
		Owner:       "admin",
		Name:        testOrg,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: testOrg,
	}
	if _, err := object.AddOrganization(organization); err != nil {
		t.Fatalf("harness problem: could not create test organization: %v", err)
	}
	defer object.DeleteOrganization(organization)

	application := &object.Application{
		Owner:        "admin",
		Name:         testApp,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  testApp,
		Organization: testOrg,
	}
	if _, err := object.AddApplication(application); err != nil {
		t.Fatalf("harness problem: could not create test application: %v", err)
	}
	defer object.DeleteApplication(application)

	standardUser := &object.User{
		Owner:       testOrg,
		Name:        standardUserName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     false,
	}
	if _, err := object.AddUser(standardUser, "en"); err != nil {
		t.Fatalf("harness problem: could not create standard test user: %v", err)
	}
	defer object.DeleteUser(standardUser)

	orgAdminUser := &object.User{
		Owner:       testOrg,
		Name:        orgAdminUserName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     true,
	}
	if _, err := object.AddUser(orgAdminUser, "en"); err != nil {
		t.Fatalf("harness problem: could not create org-admin test user: %v", err)
	}
	defer object.DeleteUser(orgAdminUser)

	victimResource := &object.Resource{
		Owner:       "built-in",
		Name:        victimResourceName,
		CreatedTime: util.GetCurrentTime(),
		User:        "admin",
		FileName:    victimResourceName + ".txt",
		FileType:    "text",
		FileFormat:  "txt",
		Url:         "http://internal.example.com/" + victimResourceName + ".txt",
		Description: "niro-regress TC-A113ABC1: built-in-admin private resource",
	}
	if _, err := object.AddResource(victimResource); err != nil {
		t.Fatalf("harness problem: could not create victim resource: %v", err)
	}
	defer object.DeleteResource(victimResource)

	crossTenantQuery := "owner=built-in&user=admin"

	t.Run("standard user cannot list another org's resources", func(t *testing.T) {
		status, msg, body := callGetResources(t, testOrg+"/"+standardUserName, crossTenantQuery)
		if status == "ok" {
			t.Fatalf("invariant violated: standard user %s/%s listed built-in's resources via owner/user query params — cross-tenant leak. body=%s", testOrg, standardUserName, body)
		}
		t.Logf("denied as expected: status=%s msg=%s", status, msg)
	})

	t.Run("org admin cannot list another org's resources", func(t *testing.T) {
		status, msg, body := callGetResources(t, testOrg+"/"+orgAdminUserName, crossTenantQuery)
		if status == "ok" {
			t.Fatalf("invariant violated: org-admin %s/%s (admin of %s only) listed built-in's resources — cross-tenant leak. body=%s", testOrg, orgAdminUserName, testOrg, body)
		}
		t.Logf("denied as expected: status=%s msg=%s", status, msg)
	})

	t.Run("control: standard user can still list their own org's resources", func(t *testing.T) {
		ownQuery := fmt.Sprintf("owner=%s&user=%s", testOrg, standardUserName)
		status, msg, body := callGetResources(t, testOrg+"/"+standardUserName, ownQuery)
		if status != "ok" {
			t.Fatalf("harness problem: standard user could not list their own organization's resources (status=%s msg=%s) — the fix over-restricted legitimate same-tenant access. body=%s", status, msg, body)
		}
	})

	t.Run("control: global admin can still list built-in's own resources", func(t *testing.T) {
		status, msg, body := callGetResources(t, "built-in/admin", crossTenantQuery)
		if status != "ok" {
			t.Fatalf("harness problem: global admin (built-in/admin) could not list built-in's own resources (status=%s msg=%s) — the fix over-restricted legitimate global-admin access. body=%s", status, msg, body)
		}
		if !bytes.Contains(body, []byte(victimResourceName)) {
			t.Fatalf("harness problem: global admin's own-org listing did not contain the built-in-owned resource %q it should legitimately see. body=%s", victimResourceName, body)
		}
	})
}
