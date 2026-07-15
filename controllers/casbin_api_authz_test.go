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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// fakeSessionStore is a minimal in-memory session.Store. A real request goes
// through beego's session middleware, which populates ctx.Input.CruSession
// before any controller method runs; a bare httptest context does not, so
// GetSessionUsername()'s fallback path (GetSessionData -> GetSession) would
// nil-panic without this. An empty fakeSessionStore correctly represents an
// unauthenticated caller: every Get returns nil, same as a real empty
// session.
type fakeSessionStore struct {
	mu   sync.Mutex
	data map[interface{}]interface{}
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{data: map[interface{}]interface{}{}}
}

func (s *fakeSessionStore) Set(_ context.Context, key, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

func (s *fakeSessionStore) Get(_ context.Context, key interface{}) interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[key]
}

func (s *fakeSessionStore) Delete(_ context.Context, key interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *fakeSessionStore) SessionID(_ context.Context) string { return "niro-regress-fake-session" }

func (s *fakeSessionStore) SessionReleaseIfPresent(_ context.Context, _ http.ResponseWriter) {}

func (s *fakeSessionStore) SessionRelease(_ context.Context, _ http.ResponseWriter) {}

func (s *fakeSessionStore) Flush(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[interface{}]interface{}{}
	return nil
}

// callCasbinGetAllEndpoint drives one of (*ApiController).GetAllRoles() /
// GetAllObjects() / GetAllActions() in-process, the same way a live HTTP
// request does, but without a real socket or session cookie:
// GetSessionUsername() reads ctx.Input.GetData("currentUserId") first, which
// is exactly what routers.ApiFilter stashes there for a real request after
// resolving the session. Setting it directly here (or leaving it unset, for
// the unauthenticated case) exercises the real, unmodified controller
// method end to end.
func callCasbinGetAllEndpoint(t *testing.T, endpoint, signedInUserId, rawQuery string) (status string, msg string, body []byte) {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/api/"+endpoint+"?"+rawQuery, nil)
	w := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(w, r)
	ctx.Input.CruSession = newFakeSessionStore()
	if signedInUserId != "" {
		ctx.Input.SetData("currentUserId", signedInUserId)
	}

	c := &ApiController{}
	var methodName string
	switch endpoint {
	case "get-all-roles":
		methodName = "GetAllRoles"
	case "get-all-objects":
		methodName = "GetAllObjects"
	case "get-all-actions":
		methodName = "GetAllActions"
	default:
		t.Fatalf("unknown endpoint %q", endpoint)
	}
	c.Init(ctx, "ApiController", methodName, nil)

	switch endpoint {
	case "get-all-roles":
		c.GetAllRoles()
	case "get-all-objects":
		c.GetAllObjects()
	case "get-all-actions":
		c.GetAllActions()
	}

	body = w.Body.Bytes()
	var parsed Response
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("%s did not return valid JSON: %v (body=%s)", methodName, err, body)
	}
	return parsed.Status, parsed.Msg, body
}

// TestGetAllEndpointsEnforceCallerOwnership is a regression test for
// TC-927F5F15: GetAllRoles(), GetAllObjects(), and GetAllActions() all used
// the userId query parameter directly, with no check against the caller's
// own session identity or admin status, whenever it was non-empty. That let
// any caller — including a fully unauthenticated one with no cookie or
// session at all — enumerate another user's assigned roles, accessible
// resources, and permitted actions just by naming that user's owner/name in
// the query string.
//
// Fixtures are created directly through the object package (this package's
// own test factories), not read from Niro's ephemeral harness seed data, so
// this test is self-contained and reproducible against any freshly booted
// instance.
func TestGetAllEndpointsEnforceCallerOwnership(t *testing.T) {
	object.InitConfig()
	object.InitUserManager()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	testOrg := "niro-regress-org-" + suffix
	victimName := "niro-regress-victim-" + suffix
	bystanderName := "niro-regress-bystander-" + suffix
	roleName := "niro-regress-role-" + suffix

	testApp := "niro-regress-app-" + suffix

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

	victimUser := &object.User{
		Owner:       testOrg,
		Name:        victimName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     false,
	}
	if _, err := object.AddUser(victimUser, "en"); err != nil {
		t.Fatalf("harness problem: could not create victim test user: %v", err)
	}
	defer object.DeleteUser(victimUser)

	bystanderUser := &object.User{
		Owner:       testOrg,
		Name:        bystanderName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     false,
	}
	if _, err := object.AddUser(bystanderUser, "en"); err != nil {
		t.Fatalf("harness problem: could not create bystander test user: %v", err)
	}
	defer object.DeleteUser(bystanderUser)

	// Reuse the pre-existing built-in/admin account as the "global admin"
	// actor rather than provisioning a new built-in-org user: adding a new
	// user to the reserved "built-in" organization is disabled by default
	// (see object.AddUser), and built-in/admin already satisfies
	// object.User.IsGlobalAdmin() (Owner == "built-in") regardless of its
	// IsAdmin flag.
	const globalAdminUserId = "built-in/admin"

	victimUserId := testOrg + "/" + victimName

	role := &object.Role{
		Owner:       testOrg,
		Name:        roleName,
		CreatedTime: util.GetCurrentTime(),
		Users:       []string{victimUserId},
		IsEnabled:   true,
	}
	if _, err := object.AddRole(role); err != nil {
		t.Fatalf("harness problem: could not create victim's role: %v", err)
	}
	defer object.DeleteRole(role)

	victimQuery := "userId=" + victimUserId

	endpoints := []string{"get-all-roles", "get-all-objects", "get-all-actions"}

	for _, endpoint := range endpoints {
		endpoint := endpoint

		t.Run(endpoint+"/unauthenticated caller cannot look up another user", func(t *testing.T) {
			status, msg, body := callCasbinGetAllEndpoint(t, endpoint, "", victimQuery)
			if status == "ok" {
				t.Fatalf("invariant violated: a fully unauthenticated caller (no session) read %s's data via the userId query parameter on %s. body=%s", victimUserId, endpoint, body)
			}
			t.Logf("denied as expected: status=%s msg=%s", status, msg)
		})

		t.Run(endpoint+"/authenticated non-owner cannot look up another user", func(t *testing.T) {
			status, msg, body := callCasbinGetAllEndpoint(t, endpoint, testOrg+"/"+bystanderName, victimQuery)
			if status == "ok" {
				t.Fatalf("invariant violated: bystander %s/%s read %s's data via the userId query parameter on %s. body=%s", testOrg, bystanderName, victimUserId, endpoint, body)
			}
			t.Logf("denied as expected: status=%s msg=%s", status, msg)
		})

		t.Run(endpoint+"/control: authenticated self-lookup still works", func(t *testing.T) {
			status, msg, body := callCasbinGetAllEndpoint(t, endpoint, victimUserId, victimQuery)
			if status != "ok" {
				t.Fatalf("harness problem: victim's own self-lookup via userId on %s unexpectedly failed (status=%s msg=%s) — the fix over-restricted legitimate self access. body=%s", endpoint, status, msg, body)
			}
		})

		t.Run(endpoint+"/control: global admin can still look up another user", func(t *testing.T) {
			status, msg, body := callCasbinGetAllEndpoint(t, endpoint, globalAdminUserId, victimQuery)
			if status != "ok" {
				t.Fatalf("harness problem: global admin (%s) could not look up %s via %s (status=%s msg=%s) — the fix over-restricted legitimate admin access. body=%s", globalAdminUserId, victimUserId, endpoint, status, msg, body)
			}
		})
	}

	// Extra assertion, specific to get-all-roles: the control response must
	// actually contain the victim's real role, proving the "control still
	// works" checks above aren't accidentally passing against an empty/
	// no-op response.
	t.Run("get-all-roles control response contains the real role data", func(t *testing.T) {
		_, _, body := callCasbinGetAllEndpoint(t, "get-all-roles", victimUserId, victimQuery)
		if !bytes.Contains(body, []byte(roleName)) {
			t.Fatalf("harness problem: victim's authenticated self-lookup on get-all-roles did not contain their real role %q. body=%s", roleName, body)
		}
	})
}
