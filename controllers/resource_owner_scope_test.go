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

// This is a black-box integration test for GetResources' tenant-isolation
// invariant: a standard signed-in user (no admin role, no membership in the
// target organization) must only see resource-file listings belonging to
// their own organization, never every organization's files on the platform.
//
// GetResources' authorization decision is made against the live HTTP
// session/request context (c.Ctx, cookies, IsOrgAdmin()), which this
// repository has no existing harness for unit-testing in isolation. This
// test instead drives the endpoint end-to-end against a running Casdoor
// instance, the same way a real client would. It is skipped automatically
// when no such instance is reachable, so it never blocks `go test ./...`
// in an environment without a live target.
//
// Point it at a running instance by setting CASDOOR_TEST_URL; the test is
// skipped when that variable is unset so `go test ./...` stays hermetic in
// environments with no live target configured. The target must have two
// organizations, each with an admin account able to sign in and create
// resources: niro-alpha/admin and niro-beta/admin (both password
// NiroPass123 by default, overridable via CASDOOR_TEST_ADMIN_PASSWORD), and
// a standard, non-admin user in niro-alpha: niro-alpha/alice (same
// password). These are throwaway dedicated test-tenant accounts, not
// production credentials.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"testing"
	"time"
)

type ownerScopeLoginReq struct {
	Application  string `json:"application"`
	Organization string `json:"organization"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	SigninMethod string `json:"signinMethod"`
	Type         string `json:"type"`
}

type ownerScopeAPIResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type ownerScopeResource struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func ownerScopeTestURL() string {
	return os.Getenv("CASDOOR_TEST_URL")
}

func ownerScopeTestPassword() string {
	if v := os.Getenv("CASDOOR_TEST_ADMIN_PASSWORD"); v != "" {
		return v
	}
	return "NiroPass123"
}

func ownerScopeNewClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 15 * time.Second}
}

func ownerScopeLogin(t *testing.T, client *http.Client, base, application, organization, username, password string) bool {
	t.Helper()
	body, _ := json.Marshal(ownerScopeLoginReq{
		Application:  application,
		Organization: organization,
		Username:     username,
		Password:     password,
		SigninMethod: "Password",
		Type:         "login",
	})
	resp, err := client.Post(base+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request for %s/%s errored: %v", organization, username, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r ownerScopeAPIResp
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("login response for %s/%s not JSON: %v\nraw=%s", organization, username, err, raw)
	}
	return r.Status == "ok"
}

func ownerScopeAddResource(t *testing.T, client *http.Client, base, owner, application, name, description string) {
	t.Helper()
	url := fmt.Sprintf("%s/api/add-resource?owner=%s&user=admin&application=%s", base, owner, application)
	payload := map[string]interface{}{
		"owner":       owner,
		"name":        name,
		"createdTime": time.Now().UTC().Format(time.RFC3339),
		"user":        "admin",
		"provider":    "",
		"application": application,
		"tag":         "regression-test",
		"parent":      "regression-test",
		"fileName":    name,
		"fileType":    "text",
		"fileFormat":  "txt",
		"fileSize":    10,
		"url":         "https://example.com/" + name,
		"description": description,
	}
	body, _ := json.Marshal(payload)
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("add-resource for owner=%s errored: %v", owner, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r ownerScopeAPIResp
	if err := json.Unmarshal(raw, &r); err != nil || r.Status != "ok" {
		t.Fatalf("add-resource for owner=%s did not succeed: raw=%s", owner, raw)
	}
}

func ownerScopeGetResources(t *testing.T, client *http.Client, base, owner, user string) (int, []ownerScopeResource, string) {
	t.Helper()
	url := fmt.Sprintf("%s/api/get-resources?owner=%s&user=%s", base, owner, user)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("get-resources request errored: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r ownerScopeAPIResp
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("get-resources response not JSON: %v\nraw=%s", err, raw)
	}
	var rows []ownerScopeResource
	_ = json.Unmarshal(r.Data, &rows) // Data may be a string ("Please login first") for the negative case.
	return resp.StatusCode, rows, r.Msg
}

// TestGetResourcesScopesToCallersOwnOrganization is the regression test for
// TC-150BD790: a standard signed-in user must never see another
// organization's resource-file listings via GET /api/get-resources.
func TestGetResourcesScopesToCallersOwnOrganization(t *testing.T) {
	base := ownerScopeTestURL()
	if base == "" {
		t.Skip("CASDOOR_TEST_URL not set; skipping live-target regression test for TC-150BD790")
	}
	password := ownerScopeTestPassword()

	healthClient := &http.Client{Timeout: 3 * time.Second}
	if resp, err := healthClient.Get(base + "/api/health"); err != nil {
		t.Skipf("no live Casdoor instance reachable at %s (set CASDOOR_TEST_URL): %v", base, err)
	} else {
		resp.Body.Close()
	}

	ts := time.Now().UnixNano()
	alphaResourceName := fmt.Sprintf("regression-alpha-secret-%d.txt", ts)
	betaResourceName := fmt.Sprintf("regression-beta-secret-%d.txt", ts)

	// Setup: each org's own admin creates one throwaway resource owned by
	// their own org, proving write-side scoping is fine and giving us two
	// distinguishable, freshly-created rows to check for cross-tenant leakage.
	alphaAdmin := ownerScopeNewClient(t)
	if !ownerScopeLogin(t, alphaAdmin, base, "app-niro-alpha", "niro-alpha", "admin", password) {
		t.Skip("could not sign in as niro-alpha/admin; live target not seeded as expected, skipping")
	}
	ownerScopeAddResource(t, alphaAdmin, base, "niro-alpha", "app-niro-alpha", alphaResourceName, "alpha confidential doc (regression test, throwaway)")

	betaAdmin := ownerScopeNewClient(t)
	if !ownerScopeLogin(t, betaAdmin, base, "app-niro-beta", "niro-beta", "admin", password) {
		t.Skip("could not sign in as niro-beta/admin; live target not seeded as expected, skipping")
	}
	ownerScopeAddResource(t, betaAdmin, base, "niro-beta", "app-niro-beta", betaResourceName, "beta confidential doc (regression test, throwaway)")

	// Positive control: an unauthenticated call must be rejected, proving the
	// target is healthy and the gate under test is "authorized for this org",
	// not merely "reachable".
	anon := &http.Client{Jar: nil, Timeout: 15 * time.Second}
	status, _, msg := ownerScopeGetResources(t, anon, base, "", "")
	if status != 200 || msg == "" {
		t.Fatalf("unauthenticated control request looked unhealthy (status=%d msg=%q); environment issue, not a security signal", status, msg)
	}

	// Victim: a standard, non-admin signed-in user in niro-alpha only.
	alice := ownerScopeNewClient(t)
	if !ownerScopeLogin(t, alice, base, "app-niro-alpha", "niro-alpha", "alice", password) {
		t.Skip("could not sign in as niro-alpha/alice; live target not seeded as expected, skipping")
	}

	// Second positive control: when Alice supplies her own org explicitly,
	// the endpoint must scope results to niro-alpha only. This isolates the
	// invariant under test to the empty-owner path, rather than a broadly
	// broken environment.
	_, scopedRows, scopedMsg := ownerScopeGetResources(t, alice, base, "niro-alpha", "")
	if scopedMsg != "" {
		t.Fatalf("alice's explicit-owner control request returned an error: %s", scopedMsg)
	}
	for _, row := range scopedRows {
		if row.Owner != "niro-alpha" {
			t.Fatalf("explicit owner=niro-alpha control leaked a %s-owned row; environment is broadly broken, not isolating the invariant under test", row.Owner)
		}
	}

	// The invariant under test: alice, a standard signed-in user with no
	// admin flag and no membership in niro-beta, must never see niro-beta's
	// resources — including via the empty-owner/empty-user query parameters.
	_, rows, msg := ownerScopeGetResources(t, alice, base, "", "")
	if msg != "" {
		t.Fatalf("alice's get-resources request returned an error, cannot evaluate: %s", msg)
	}

	sawOwnOrgResource := false
	var leaked *ownerScopeResource
	for i, row := range rows {
		if row.Owner == "niro-alpha" && row.Name == alphaResourceName {
			sawOwnOrgResource = true
		}
		if row.Owner == "niro-beta" && row.Name == betaResourceName {
			leaked = &rows[i]
		}
	}

	if !sawOwnOrgResource {
		t.Fatalf("alice did not even see her own org's resource; harness/setup problem, not a clean signal")
	}

	if leaked != nil {
		t.Fatalf("tenant isolation violated: standard user niro-alpha/alice (no admin) saw a cross-tenant resource via GET /api/get-resources?owner=&user= "+
			"(owner=%s name=%s description=%q); total rows=%d, expected only niro-alpha rows",
			leaked.Owner, leaked.Name, leaked.Description, len(rows))
	}
}
