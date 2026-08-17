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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// recordApiTestSetup boots just enough of the app (config + DB connection +
// an in-memory session manager) for ApiController methods to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used by object package tests (see object/user_test.go, which calls
// object.InitConfig() directly against a real database).
var recordApiTestSetup sync.Once

func initRecordApiTest(t *testing.T) {
	t.Helper()

	recordApiTestSetup.Do(func() {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			panic("failed to resolve test file path")
		}
		repoRoot := filepath.Dir(filepath.Dir(thisFile))

		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id_test"
		web.BConfig.WebConfig.Session.SessionGCMaxLifetime = 3600

		// Loads conf/app.conf (real MySQL DSN) and registers beego's session
		// manager, mirroring what main.go does at startup.
		web.TestBeegoInit(repoRoot)

		object.InitAdapter()
		object.CreateTables()
		object.InitDb()
		object.InitUserManager()
	})
}

// setupRecordApiOrg creates an organization plus one application for it (an
// application is required before any user can be added to a non-built-in
// organization), and registers cleanup.
func setupRecordApiOrg(t *testing.T, orgName string) {
	t.Helper()

	org := &object.Organization{
		Owner:       "admin",
		Name:        orgName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: orgName,
	}
	ok, err := object.AddOrganization(org)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture organization %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(org) })

	app := &object.Application{
		Owner:        "admin",
		Name:         "app-" + orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "app-" + orgName,
		Organization: orgName,
	}
	ok, err = object.AddApplication(app)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture application for %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })
}

// setupRecordApiUser creates a user in orgName and registers cleanup.
func setupRecordApiUser(t *testing.T, orgName, name string, isAdmin bool) *object.User {
	t.Helper()

	user := &object.User{
		Owner:       orgName,
		Name:        name,
		Id:          orgName + "/" + name,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: name,
		IsAdmin:     isAdmin,
	}
	ok, err := object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s/%s: ok=%v err=%v", orgName, name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// addRecordApiTestRecord inserts a Record belonging to orgName directly,
// mirroring what object.AddRecord does when the audit-log middleware logs a
// real request (see object/record.go AddRecord). Uses Method "POST" so it
// isn't skipped by the logPostOnly=true setting in conf/app.conf.
func addRecordApiTestRecord(t *testing.T, orgName, name, action string) {
	t.Helper()

	record := &object.Record{
		Owner:        orgName,
		Name:         name,
		CreatedTime:  util.GetCurrentTime(),
		Organization: orgName,
		ClientIp:     "127.0.0.1",
		User:         "admin",
		Method:       "POST",
		RequestUri:   "/api/login",
		Action:       action,
		Object:       fmt.Sprintf(`{"organization":%q,"password":"super-secret"}`, orgName),
		Response:     `{status:"ok"}`,
	}
	if ok := object.AddRecord(record); !ok {
		t.Fatalf("failed to insert fixture record for org %s", orgName)
	}
}

// callGetRecords drives ApiController.GetRecords directly, simulating GET
// /api/get-records[?query] with the given session username -- the same seam
// the vulnerability lived in.
func callGetRecords(t *testing.T, sessionUsername, query string) *Response {
	t.Helper()

	target := "/api/get-records"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(w, req)

	sess, err := web.GlobalSessions.SessionStart(w, req)
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	defer sess.SessionRelease(context.Background(), w)
	ctx.Input.CruSession = sess

	if sessionUsername != "" {
		if err := sess.Set(context.Background(), "username", sessionUsername); err != nil {
			t.Fatalf("failed to set session username: %v", err)
		}
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetRecords", nil)
	c.GetRecords()

	resp := &Response{}
	if err := json.Unmarshal(w.Body.Bytes(), resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), err)
	}
	return resp
}

// recordOrgs extracts the set of "organization" values present in a
// GetRecords response's Data payload.
func recordOrgs(t *testing.T, resp *Response) map[string]int {
	t.Helper()

	orgs := map[string]int{}
	arr, ok := resp.Data.([]interface{})
	if !ok {
		return orgs
	}
	for _, v := range arr {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		org, _ := m["organization"].(string)
		orgs[org]++
	}
	return orgs
}

// TestGetRecordsUnpaginatedScopesToCallerOrganization is the regression test
// for TC-6338D432: the unpaginated GET /api/get-records path (no
// pageSize/p) must scope results to the caller's own organization exactly
// like the paginated path already does, instead of returning every
// organization's audit records (including other tenants' request bodies,
// which can carry plaintext passwords/tokens).
func TestGetRecordsUnpaginatedScopesToCallerOrganization(t *testing.T) {
	initRecordApiTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgAlpha := "record-it-alpha-" + suffix
	orgBeta := "record-it-beta-" + suffix

	setupRecordApiOrg(t, orgAlpha)
	setupRecordApiOrg(t, orgBeta)

	alphaAdmin := setupRecordApiUser(t, orgAlpha, "admin", true)

	addRecordApiTestRecord(t, orgAlpha, "record-alpha-"+suffix, "login")
	addRecordApiTestRecord(t, orgBeta, "record-beta-"+suffix, "login")

	// Positive control: the paginated path must return only orgAlpha
	// records for the orgAlpha admin. Proves the org filter/fixtures/session
	// are healthy so the red case below isolates the real bug.
	t.Run("control_paginated_scopes_to_caller_org", func(t *testing.T) {
		resp := callGetRecords(t, alphaAdmin.GetId(), "pageSize=100&p=1")
		if resp.Status != "ok" {
			t.Fatalf("paginated get-records failed for orgAlpha admin: %+v", resp)
		}
		orgs := recordOrgs(t, resp)
		if orgs[orgAlpha] == 0 {
			t.Fatalf("control failed: paginated response did not contain any orgAlpha records: %v", orgs)
		}
		if orgs[orgBeta] != 0 {
			t.Fatalf("control failed: paginated response unexpectedly contained orgBeta records: %v", orgs)
		}
	})

	// Red/green case: the unpaginated path (no pageSize/p) must ALSO scope
	// to orgAlpha only, never leaking orgBeta's records to the orgAlpha
	// tenant admin.
	t.Run("unpaginated_rejects_foreign_org_records", func(t *testing.T) {
		resp := callGetRecords(t, alphaAdmin.GetId(), "")
		if resp.Status != "ok" {
			t.Fatalf("unpaginated get-records failed for orgAlpha admin: %+v", resp)
		}
		orgs := recordOrgs(t, resp)
		if orgs[orgBeta] != 0 {
			t.Fatalf("INVARIANT VIOLATED: orgAlpha tenant admin received %d record(s) belonging to orgBeta via the unpaginated /api/get-records endpoint: %v", orgs[orgBeta], orgs)
		}
		if orgs[orgAlpha] == 0 {
			t.Fatalf("unpaginated response unexpectedly contained no orgAlpha records either: %v", orgs)
		}
	})

	// Positive control: the platform's built-in global admin must keep
	// seeing records across every organization on the unpaginated path --
	// the fix must scope org-scoped admins without narrowing the
	// global-admin view that legitimately spans all tenants.
	t.Run("control_global_admin_still_sees_all_orgs_unpaginated", func(t *testing.T) {
		resp := callGetRecords(t, "built-in/admin", "")
		if resp.Status != "ok" {
			t.Fatalf("unpaginated get-records failed for global admin: %+v", resp)
		}
		orgs := recordOrgs(t, resp)
		if orgs[orgAlpha] == 0 || orgs[orgBeta] == 0 {
			t.Fatalf("control failed: global admin should still see records from both orgAlpha and orgBeta unpaginated, got: %v", orgs)
		}
	})
}
