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

//go:build !skipCi

package controllers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	beego "github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
	"github.com/casdoor/casdoor/util"
)

var initAppOnce sync.Once

// initTestApp brings up the same DB connection, session manager, and API
// route table the real server (main.go) wires up, in-process, so this test
// can drive controllers.ApiController the way a real client would: over
// HTTP, through beego's own router and session middleware.
func initTestApp() {
	initAppOnce.Do(func() {
		object.InitConfig()
		beego.InitBeegoBeforeTest("../conf/app.conf")
		routers.InitAPI()
	})
}

type testApiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type testRecordDTO struct {
	Id           int    `json:"id"`
	Organization string `json:"organization"`
	Action       string `json:"action"`
}

// doTestRequest performs one in-process HTTP round trip against beego's own
// router, carrying cookies forward like a real browser session.
func doTestRequest(t *testing.T, method, path string, body []byte, cookies []*http.Cookie) (*http.Response, []byte) {
	t.Helper()

	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, path, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequest(method, path, nil)
	}
	if err != nil {
		t.Fatalf("building request %s %s: %v", method, path, err)
	}
	req.RemoteAddr = "127.0.0.1:12345"
	for _, c := range cookies {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	beego.BeeApp.Handlers.ServeHTTP(w, req)

	resp := w.Result()
	return resp, w.Body.Bytes()
}

// setupOrgAdminWithRecords creates a brand-new organization, application,
// and org-scoped (non-global) admin user - plus a handful of audit-log
// Records seeded directly in the admin's own organization and in a sibling
// organization the admin must never be able to read.
func setupOrgAdminWithRecords(t *testing.T) (orgName, appName, adminUsername, adminPassword, otherOrgName string) {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName = "nirotest-org-" + suffix
	otherOrgName = "nirotest-other-" + suffix
	appName = "nirotest-app-" + suffix
	adminUsername = "nirotest-admin-" + suffix
	adminPassword = "NiroTest-Pw1!"
	now := time.Now().Format(time.RFC3339)

	org := &object.Organization{
		Owner:        "admin",
		Name:         orgName,
		CreatedTime:  now,
		DisplayName:  orgName,
		PasswordType: "plain",
	}
	if ok, err := object.AddOrganization(org); err != nil || !ok {
		t.Fatalf("AddOrganization(%s) failed: ok=%v err=%v", orgName, ok, err)
	}

	otherOrg := &object.Organization{
		Owner:        "admin",
		Name:         otherOrgName,
		CreatedTime:  now,
		DisplayName:  otherOrgName,
		PasswordType: "plain",
	}
	if ok, err := object.AddOrganization(otherOrg); err != nil || !ok {
		t.Fatalf("AddOrganization(%s) failed: ok=%v err=%v", otherOrgName, ok, err)
	}

	app := &object.Application{
		Owner:          "admin",
		Name:           appName,
		CreatedTime:    now,
		DisplayName:    appName,
		Organization:   orgName,
		EnablePassword: true,
	}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("AddApplication(%s) failed: ok=%v err=%v", appName, ok, err)
	}

	admin := &object.User{
		Owner:       orgName,
		Name:        adminUsername,
		CreatedTime: now,
		Id:          util.GenerateId(),
		Type:        "normal-user",
		Password:    adminPassword,
		DisplayName: adminUsername,
		IsAdmin:     true,
	}
	if ok, err := object.AddUser(admin, "en"); err != nil || !ok {
		t.Fatalf("AddUser(%s) failed: ok=%v err=%v", adminUsername, ok, err)
	}

	// Seed audit-log records directly (bypassing the HTTP RecordMessage
	// filter chain, which main.go wires up outside routers.InitAPI() and
	// which delivers asynchronously) in both the admin's own organization
	// and a sibling organization the admin must never see.
	seedRecord := func(organization, action string) {
		ok := object.AddRecord(&object.Record{
			Name:         util.GenerateId(),
			CreatedTime:  time.Now().Format(time.RFC3339),
			Organization: organization,
			User:         adminUsername,
			// AddRecord silently drops the record when logPostOnly is set
			// (conf/app.conf default) and Method == "GET", so use POST.
			Method: "POST",
			Action: action,
			Object: fmt.Sprintf(`{"marker":"%s"}`, action),
		})
		if !ok {
			t.Fatalf("AddRecord(organization=%s, action=%s) reported not-affected", organization, action)
		}
	}
	seedRecord(orgName, "nirotest-own-record-a-"+suffix)
	seedRecord(orgName, "nirotest-own-record-b-"+suffix)
	seedRecord(otherOrgName, "nirotest-other-record-"+suffix)

	return orgName, appName, adminUsername, adminPassword, otherOrgName
}

func testLogin(t *testing.T, username, password, organization, application string) []*http.Cookie {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"type":         "login",
		"signinMethod": "Password",
		"username":     username,
		"password":     password,
		"organization": organization,
		"application":  application,
	})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}

	resp, raw := doTestRequest(t, http.MethodPost, "/api/login", body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login HTTP status = %d, body = %s", resp.StatusCode, raw)
	}

	var lr testApiResponse
	if err := json.Unmarshal(raw, &lr); err != nil {
		t.Fatalf("unmarshal login response %s: %v", raw, err)
	}
	if lr.Status != "ok" {
		t.Fatalf("login rejected: status=%q msg=%q body=%s", lr.Status, lr.Msg, raw)
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login succeeded but no session cookie was set; body=%s", raw)
	}
	return cookies
}

// TestGetRecordsUnpaginatedIsScopedToCallerOrganization is the regression
// test for TC-60B4236C: an organization-scoped (non-global) admin must only
// ever see audit-log records belonging to their own organization, whether
// or not pagination params (pageSize/p) are supplied to GET /api/get-records.
func TestGetRecordsUnpaginatedIsScopedToCallerOrganization(t *testing.T) {
	initTestApp()

	orgName, appName, adminUsername, adminPassword, otherOrgName := setupOrgAdminWithRecords(t)

	cookies := testLogin(t, adminUsername, adminPassword, orgName, appName)

	// --- Positive control: the paginated branch must be org-scoped. ---
	// This proves the session/auth/environment are healthy and that an org
	// filter genuinely exists in this handler, so a failure below is the
	// invariant breaking - not a broken harness.
	pagResp, pagRaw := doTestRequest(t, http.MethodGet, "/api/get-records?pageSize=50&p=1", nil, cookies)
	if pagResp.StatusCode != http.StatusOK {
		t.Fatalf("paginated GET /api/get-records HTTP status = %d, body = %s", pagResp.StatusCode, pagRaw)
	}
	var pagEnvelope testApiResponse
	if err := json.Unmarshal(pagRaw, &pagEnvelope); err != nil {
		t.Fatalf("unmarshal paginated response %s: %v", pagRaw, err)
	}
	if pagEnvelope.Status != "ok" {
		t.Fatalf("paginated request failed: status=%q msg=%q", pagEnvelope.Status, pagEnvelope.Msg)
	}
	var pagRecords []testRecordDTO
	if err := json.Unmarshal(pagEnvelope.Data, &pagRecords); err != nil {
		t.Fatalf("unmarshal paginated records %s: %v", pagEnvelope.Data, err)
	}
	if len(pagRecords) == 0 {
		t.Fatalf("positive control returned zero records; cannot validate environment health")
	}
	for _, r := range pagRecords {
		if r.Organization != orgName {
			t.Fatalf("positive control (paginated branch) itself leaked cross-org record id=%d org=%q; environment is broadly broken, not isolating the bug under test", r.Id, r.Organization)
		}
	}

	// --- Red check: the UNPAGINATED branch must ALSO be org-scoped. ---
	// This is the invariant under test: an org-scoped (non-global) admin
	// must never see another organization's audit records, regardless of
	// whether pagination params are supplied.
	unpagResp, unpagRaw := doTestRequest(t, http.MethodGet, "/api/get-records", nil, cookies)
	if unpagResp.StatusCode != http.StatusOK {
		t.Fatalf("unpaginated GET /api/get-records HTTP status = %d, body = %s", unpagResp.StatusCode, unpagRaw)
	}
	var unpagEnvelope testApiResponse
	if err := json.Unmarshal(unpagRaw, &unpagEnvelope); err != nil {
		t.Fatalf("unmarshal unpaginated response %s: %v", unpagRaw, err)
	}
	if unpagEnvelope.Status != "ok" {
		t.Fatalf("unpaginated request failed: status=%q msg=%q", unpagEnvelope.Status, unpagEnvelope.Msg)
	}
	var unpagRecords []testRecordDTO
	if err := json.Unmarshal(unpagEnvelope.Data, &unpagRecords); err != nil {
		t.Fatalf("unmarshal unpaginated records %s: %v", unpagEnvelope.Data, err)
	}

	for _, r := range unpagRecords {
		if r.Organization != orgName {
			t.Fatalf(
				"invariant violated: unpaginated /api/get-records returned a record outside org %q: id=%d org=%q action=%q (sibling org=%q); "+
					"an org-scoped admin must only ever see their own organization's audit records",
				orgName, r.Id, r.Organization, r.Action, otherOrgName)
		}
	}
}
