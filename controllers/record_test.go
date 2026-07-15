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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var recordTestEnvOnce sync.Once

func setupRecordTestEnv(t *testing.T) {
	t.Helper()
	recordTestEnvOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
		object.InitUserManager()
	})
}

// newRecordTestController builds a real *ApiController wired to an
// in-memory request/response pair, the same way beego's router does for a
// live request. currentUserId mirrors what routers/authz_filter.go's
// ApiFilter stashes on the context after authenticating the caller: it is
// set on *every* request, including an empty string for an
// anonymous/unauthenticated caller. Setting it unconditionally here (rather
// than only for authenticated callers) matters: it is what lets
// GetSessionUsername() short-circuit before touching the beego session
// store, which this bare test context does not have configured.
// callerIp becomes the request's RemoteAddr, standing in for the real
// network address of the caller.
func newRecordTestController(method, url string, body []byte, currentUserId, callerIp, actionName string) (*ApiController, *httptest.ResponseRecorder) {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	req.Header.Set("Content-Type", "application/json")
	if callerIp != "" {
		req.RemoteAddr = callerIp + ":54321"
	}

	w := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(w, req)
	ctx.Input.SetData("currentUserId", currentUserId)
	if body != nil {
		ctx.Input.RequestBody = body
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", actionName, c)
	return c, w
}

func decodeRecordResponse(t *testing.T, w *httptest.ResponseRecorder) Response {
	t.Helper()
	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), err)
	}
	return resp
}

// createRecordTestOrg seeds a minimal organization + application pair (the
// application is required by object.AddUser's "organization should have one
// application at least" check for any non-built-in org) and registers
// cleanup.
func createRecordTestOrg(t *testing.T, orgName string) {
	t.Helper()

	ok, err := object.AddOrganization(&object.Organization{
		Owner:       "admin",
		Name:        orgName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: orgName,
	})
	if err != nil || !ok {
		t.Fatalf("setup: AddOrganization(%s) = (%v, %v), want (true, nil)", orgName, ok, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteOrganization(&object.Organization{Owner: "admin", Name: orgName})
	})

	appName := "app-" + orgName
	appOk, err := object.AddApplication(&object.Application{
		Owner:        "admin",
		Name:         appName,
		CreatedTime:  util.GetCurrentTime(),
		Organization: orgName,
	})
	if err != nil || !appOk {
		t.Fatalf("setup: AddApplication(%s) = (%v, %v), want (true, nil)", appName, appOk, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteApplication(&object.Application{Owner: "admin", Name: appName})
	})
}

// createRecordTestUser seeds a user under org (created by
// createRecordTestOrg) and registers cleanup. Returns the user's "owner/name"
// session id.
func createRecordTestUser(t *testing.T, org, name string, isAdmin bool) string {
	t.Helper()

	user := &object.User{
		Owner:       org,
		Name:        name,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     isAdmin,
		Password:    "Record-Test-Pw1!",
	}
	ok, err := object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("setup: AddUser(%s/%s) = (%v, %v), want (true, nil)", org, name, ok, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteUser(user)
	})

	return org + "/" + name
}

// TestAddRecordRequiresAdminAndDerivesActorServerSide is the regression test
// for TC-DA97E1E4: /api/add-record had no auth check at all and persisted
// client-supplied organization/user/clientIp verbatim, letting any
// authenticated caller insert an audit-log entry that misattributes an
// action (including a destructive one) to an arbitrary user, organization,
// and source IP.
//
// Invariant under test: a user must not be able to insert a fabricated
// audit-log entry that misrepresents who performed an action, from what
// organization, or from what network address.
func TestAddRecordRequiresAdminAndDerivesActorServerSide(t *testing.T) {
	setupRecordTestEnv(t)

	org := "record-test-org-" + util.GenerateId()
	createRecordTestOrg(t, org)

	aliceId := createRecordTestUser(t, org, "alice", false)       // non-admin
	orgAdminId := createRecordTestUser(t, org, "org-admin", true) // org-scoped admin

	const forgedIP = "203.0.113.66"
	const callerIP = "198.51.100.7"

	forgedBody := func(action string) []byte {
		b, _ := json.Marshal(map[string]interface{}{
			"organization": "built-in",
			"clientIp":     forgedIP,
			"user":         "built-in/admin",
			"method":       "POST",
			"requestUri":   "/api/delete-organization",
			"action":       action,
			"response":     `{"status":"ok"}`,
			"statusCode":   200,
			"isTriggered":  true,
		})
		return b
	}

	// --- Step 1: a non-admin, authenticated caller must be denied
	// outright - record ingestion should require admin, matching
	// GetRecords()/GetRecordsByFilter(). ---
	deniedMarker := "record-test-denied-" + util.GenerateId()
	c, w := newRecordTestController(http.MethodPost, "/api/add-record", forgedBody(deniedMarker), aliceId, callerIP, "AddRecord")
	c.AddRecord()
	resp := decodeRecordResponse(t, w)
	if resp.Status != "error" {
		t.Fatalf("RED (invariant violated): non-admin caller %q was allowed to call /api/add-record: %+v", aliceId, resp)
	}
	if recs, err := object.GetRecordsByField(&object.Record{Action: deniedMarker}); err != nil {
		t.Fatalf("GetRecordsByField error: %v", err)
	} else if len(recs) != 0 {
		t.Fatalf("non-admin's forged record was persisted despite a denied request: %+v", recs)
	}

	// --- Step 2: an org-scoped admin is allowed to call the endpoint (the
	// admin gate itself), but the persisted organization/user/clientIp must
	// be derived server-side from the authenticated session and the real
	// request, never trusted from the JSON body - even though the caller
	// tried to impersonate built-in/admin acting from an arbitrary IP. ---
	forgedMarker := "record-test-forged-" + util.GenerateId()
	c, w = newRecordTestController(http.MethodPost, "/api/add-record", forgedBody(forgedMarker), orgAdminId, callerIP, "AddRecord")
	c.AddRecord()
	resp = decodeRecordResponse(t, w)
	if resp.Status != "ok" {
		t.Fatalf("positive control failed: org admin %q was denied /api/add-record: %+v", orgAdminId, resp)
	}

	recs, err := object.GetRecordsByField(&object.Record{Action: forgedMarker})
	if err != nil {
		t.Fatalf("GetRecordsByField error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected exactly one persisted record for action %q, got %d: %+v", forgedMarker, len(recs), recs)
	}

	got := recs[0]
	if got.Organization == "built-in" || got.User == "built-in/admin" || got.ClientIp == forgedIP {
		t.Fatalf("RED (invariant violated): org admin %q forged a record attributing a destructive action to organization=%q user=%q clientIp=%q - the server persisted client-supplied identity/network fields verbatim",
			orgAdminId, got.Organization, got.User, got.ClientIp)
	}
	if got.Organization != org || got.User != "org-admin" || got.ClientIp != callerIP {
		t.Fatalf("server-side derivation mismatch: got organization=%q user=%q clientIp=%q, want organization=%q user=%q clientIp=%q",
			got.Organization, got.User, got.ClientIp, org, "org-admin", callerIP)
	}
}

// TestGetRecordsUnpaginatedScopesToCallerOrganization is the regression test
// for TC-77BAF6DD: GET /api/get-records, when called with no pageSize/p
// query params, ran an unfiltered query across every organization's audit
// records instead of scoping to the caller's own organization - unlike the
// paginated branch, which does filter correctly.
//
// Invariant under test: an organization-scoped administrator must not be
// able to view another organization's audit/activity log entries; audit
// record listing must always be filtered to the caller's own organization
// unless the caller is a true instance-wide administrator.
func TestGetRecordsUnpaginatedScopesToCallerOrganization(t *testing.T) {
	setupRecordTestEnv(t)

	orgA := "record-test-org-a-" + util.GenerateId()
	orgB := "record-test-org-b-" + util.GenerateId()
	createRecordTestOrg(t, orgA)
	createRecordTestOrg(t, orgB)

	aliceId := createRecordTestUser(t, orgA, "alice", false)        // non-admin, orgA
	orgAAdminId := createRecordTestUser(t, orgA, "org-admin", true) // org-scoped admin, orgA
	createRecordTestUser(t, orgB, "org-b-user", false)              // unrelated orgB principal

	ownMarker := "record-test-own-" + util.GenerateId()
	victimMarker := "record-test-victim-" + util.GenerateId()

	if !object.AddRecord(&object.Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: orgA,
		User:         "org-admin",
		Method:       "POST",
		RequestUri:   "/api/own-action",
		Action:       ownMarker,
		StatusCode:   200,
	}) {
		t.Fatal("setup: failed to seed orgA's own record")
	}
	if !object.AddRecord(&object.Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: orgB,
		User:         "org-b-user",
		Method:       "POST",
		RequestUri:   "/api/login",
		Action:       victimMarker,
		StatusCode:   200,
	}) {
		t.Fatal("setup: failed to seed orgB's victim record")
	}

	// --- positive control: a non-admin caller must be denied outright,
	// proving the RequireAdmin gate itself is healthy. ---
	c, w := newRecordTestController(http.MethodGet, "/api/get-records", nil, aliceId, "192.0.2.10", "GetRecords")
	c.GetRecords()
	resp := decodeRecordResponse(t, w)
	if resp.Status == "ok" {
		t.Fatalf("SETUP FAILURE: non-admin %q was allowed to call /api/get-records - environment is not healthy enough to isolate this finding", aliceId)
	}

	// --- the actual invariant: an org-scoped admin, on the unpaginated
	// path (no pageSize/p query params), must only see its own
	// organization's records. ---
	c, w = newRecordTestController(http.MethodGet, "/api/get-records", nil, orgAAdminId, "192.0.2.11", "GetRecords")
	c.GetRecords()
	resp = decodeRecordResponse(t, w)
	if resp.Status != "ok" {
		t.Fatalf("positive control failed: org admin %q was denied /api/get-records: %+v", orgAAdminId, resp)
	}

	dataBytes, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatalf("could not re-marshal response data: %v", err)
	}
	var records []*object.Record
	if err := json.Unmarshal(dataBytes, &records); err != nil {
		t.Fatalf("could not decode records: %v", err)
	}

	foundOwn := false
	for _, r := range records {
		if r.Action == victimMarker {
			t.Fatalf("RED (invariant violated): org-scoped admin of %q saw org %q's record (action=%q, user=%q) via unpaginated /api/get-records",
				orgA, orgB, r.Action, r.User)
		}
		if r.Action == ownMarker {
			foundOwn = true
		}
	}
	if !foundOwn {
		t.Fatalf("positive control failed: org admin could not see its own org's record (action=%q) among %d returned records", ownMarker, len(records))
	}
}
