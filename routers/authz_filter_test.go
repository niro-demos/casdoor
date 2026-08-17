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

package routers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// newTestContext builds a beego *context.Context wrapping an httptest
// request/response pair, the way getObject() expects to receive it from the
// real request pipeline, without needing a running server.
func newTestContext(t *testing.T, method, target string, body []byte) *context.Context {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Content-Type", "application/json")

	ctx := context.NewContext()
	ctx.Reset(httptest.NewRecorder(), req)
	// getObject() reads the raw body directly from ctx.Input.RequestBody
	// (populated in production by RequestBodyFilter earlier in the filter
	// chain), so set it directly here rather than relying on that filter.
	ctx.Input.RequestBody = body

	return ctx
}

// TC-80C2CC98 / TC-076EA838: GET /api/get-session must be authorized on
// `sessionPkId` -- the same parameter controllers/session.go's
// GetSingleSession() actually reads to fetch the record -- never on the
// unrelated `id` query parameter. Before the fix, a caller could set `id` to
// their own identity as a decoy (satisfying the self-access authz rule)
// while `sessionPkId` named a different account's session, leaking that
// account's live session-store IDs.
func TestGetObjectGetSessionUsesSessionPkIdNotDecoyId(t *testing.T) {
	ctx := newTestContext(t, http.MethodGet,
		"/api/get-session?sessionPkId=built-in/admin/app-built-in&id=niro-alpha/alice", nil)

	owner, name, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject returned unexpected error: %v", err)
	}

	if owner != "built-in" || name != "admin" {
		t.Fatalf("getObject authorized the request against the decoy `id` (niro-alpha/alice) instead of `sessionPkId` (built-in/admin/app-built-in): got owner=%q name=%q", owner, name)
	}
}

// Positive control: with no decoy `id` present, a legitimate get-session
// request must still resolve its authorization object from sessionPkId.
func TestGetObjectGetSessionWithoutDecoyIdStillResolvesFromSessionPkId(t *testing.T) {
	ctx := newTestContext(t, http.MethodGet,
		"/api/get-session?sessionPkId=niro-alpha/admin/app-niro-alpha", nil)

	owner, name, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject returned unexpected error: %v", err)
	}

	if owner != "niro-alpha" || name != "admin" {
		t.Fatalf("legitimate get-session request did not resolve from sessionPkId: got owner=%q name=%q", owner, name)
	}
}

// TC-46ED800E: POST /api/delete-group must be authorized on the JSON body's
// owner/name -- the same fields controllers/group.go's DeleteGroup() actually
// deletes -- never on the `id` query parameter, which that handler never
// reads at all. Before the fix, a tenant admin could pass `id` naming an
// object in their own org (satisfying the `subOwner == objOwner` admin rule)
// while the JSON body named an object in a different tenant, and the
// controller would delete that different tenant's object.
func TestGetObjectDeleteGroupUsesBodyOwnerNotDecoyId(t *testing.T) {
	body := []byte(`{"owner":"niro-beta","name":"victim-group"}`)
	ctx := newTestContext(t, http.MethodPost, "/api/delete-group?id=niro-alpha/decoy-group", body)

	owner, name, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject returned unexpected error: %v", err)
	}

	if owner != "niro-beta" || name != "victim-group" {
		t.Fatalf("getObject authorized delete-group against the decoy `id` (niro-alpha/decoy-group) instead of the JSON body (niro-beta/victim-group), which is what DeleteGroup() actually deletes: got owner=%q name=%q", owner, name)
	}
}

// TC-46ED800E: same query/body mismatch for POST /api/delete-user against
// controllers/user.go's DeleteUser(), which likewise deletes whatever
// owner/name is in the JSON body and never consults `id`.
func TestGetObjectDeleteUserUsesBodyOwnerNotDecoyId(t *testing.T) {
	body := []byte(`{"owner":"niro-beta","name":"victim-user"}`)
	ctx := newTestContext(t, http.MethodPost, "/api/delete-user?id=niro-alpha/admin", body)

	owner, name, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject returned unexpected error: %v", err)
	}

	if owner != "niro-beta" || name != "victim-user" {
		t.Fatalf("getObject authorized delete-user against the decoy `id` (niro-alpha/admin) instead of the JSON body (niro-beta/victim-user), which is what DeleteUser() actually deletes: got owner=%q name=%q", owner, name)
	}
}

// Positive control: a legitimate, non-spoofed delete-group request (where
// `id` and the JSON body agree) must still resolve to the same object that
// gets deleted, so the fix doesn't regress the common case.
func TestGetObjectDeleteGroupWithMatchingIdAndBodyStillWorks(t *testing.T) {
	body := []byte(`{"owner":"niro-alpha","name":"vip-group"}`)
	ctx := newTestContext(t, http.MethodPost, "/api/delete-group?id=niro-alpha/vip-group", body)

	owner, name, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject returned unexpected error: %v", err)
	}

	if owner != "niro-alpha" || name != "vip-group" {
		t.Fatalf("legitimate, non-spoofed delete-group request did not resolve to the object it actually deletes: got owner=%q name=%q", owner, name)
	}
}
