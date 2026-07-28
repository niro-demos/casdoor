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

package controllers

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// newAuthzTestApiController builds a minimal, fully wired ApiController for
// a GET request against methodName, with the signed-in user set exactly the
// way the real production auth filter sets it (routers/authz_filter.go calls
// ctx.Input.SetData("currentUserId", username)), so GetSessionUsername()
// resolves it without needing a real HTTP session/cookie stack. An empty
// currentUserId leaves the request unauthenticated, matching a caller with
// no cookies and no Authorization header at all.
func newAuthzTestApiController(rawURL, methodName, currentUserId string) *ApiController {
	req := httptest.NewRequest("GET", rawURL, nil)
	w := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", methodName, nil)
	// The real auth filter (routers/authz_filter.go ApiFilter) always calls
	// SetData("currentUserId", username), setting it to "" for an anonymous
	// caller rather than leaving it unset. GetSessionUsername() relies on
	// that: an empty *string* short-circuits to "", while a truly *unset*
	// value falls through to beego's session store (which isn't configured
	// in this bare test context and would panic). Always setting it here,
	// including the empty-string case, matches production and keeps
	// unauthenticated requests exercising the real "no session" code path
	// instead of an artifact of the test harness.
	c.Ctx.Input.SetData("currentUserId", currentUserId)
	return c
}

func seedAuthzTestUser(t *testing.T, owner, name string, isAdmin bool) string {
	t.Helper()
	id := owner + "/" + name
	existing, err := object.GetUser(id)
	if err != nil {
		t.Fatalf("failed to check for existing test user %s: %v", id, err)
	}
	if existing != nil {
		return id
	}

	user := &object.User{
		Owner:   owner,
		Name:    name,
		Id:      owner + "-" + name + "-tc9989ddb0",
		IsAdmin: isAdmin,
	}
	// AddUsers() is the syncer/batch-upload insert path: unlike AddUser(), it
	// doesn't run signup-flow business rules (e.g. the "built-in" org signup
	// guard), so it seeds a plain user row for either org used by this test.
	affected, err := object.AddUsers([]*object.User{user})
	if err != nil || !affected {
		t.Fatalf("failed to seed test user %s: affected=%v err=%v", id, affected, err)
	}
	// Deliberately not cleaned up via object.DeleteUser(): that call requires
	// the package-level user/group enforcer to be initialized from seed data
	// this bare test database doesn't have. The "existing != nil" check above
	// makes reseeding idempotent across repeated test runs instead.
	return id
}

// seedAuthzTestEntitlement grants targetUserId a uniquely-named permission
// (over a uniquely-named resource) and a uniquely-named role, mirroring the
// live PoC: isolated, freshly-created fixtures rather than shared/ambiguous
// data, so a positive hit in a response body is unambiguous proof of a leak.
func seedAuthzTestEntitlement(t *testing.T, owner, targetUserId, suffix string) (resourceName, roleName string) {
	t.Helper()

	resourceName = "tc9989ddb0-secret-app-" + suffix
	permission := &object.Permission{
		Owner:        owner,
		Name:         "tc9989ddb0-secret-perm-" + suffix,
		CreatedTime:  "2026-01-01T00:00:00Z",
		Users:        []string{targetUserId},
		ResourceType: "Application",
		Resources:    []string{resourceName},
		Actions:      []string{"Read", "Write"},
		Effect:       "Allow",
		IsEnabled:    true,
	}
	affected, err := object.AddPermission(permission)
	if err != nil || !affected {
		t.Fatalf("failed to seed test permission for %s: affected=%v err=%v", targetUserId, affected, err)
	}
	t.Cleanup(func() { _, _ = object.DeletePermission(permission) })

	roleName = "tc9989ddb0-secret-role-" + suffix
	role := &object.Role{
		Owner:       owner,
		Name:        roleName,
		CreatedTime: "2026-01-01T00:00:00Z",
		Users:       []string{targetUserId},
		IsEnabled:   true,
	}
	roleAffected, err := object.AddRole(role)
	if err != nil || !roleAffected {
		t.Fatalf("failed to seed test role for %s: affected=%v err=%v", targetUserId, roleAffected, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteRole(role) })

	return resourceName, roleName
}

func dataContainsString(data interface{}, needle string) bool {
	arr, ok := data.([]string)
	if ok {
		for _, s := range arr {
			if s == needle {
				return true
			}
		}
		return false
	}
	// object.GetAllObjects/Actions/Roles return []string, but the response
	// travels through the controller's own JSON plumbing in some code
	// paths, so also handle the []interface{} shape defensively.
	arrI, ok := data.([]interface{})
	if !ok {
		return false
	}
	for _, v := range arrI {
		if s, ok := v.(string); ok && s == needle {
			return true
		}
	}
	return false
}

// TestGetAllEndpointsEnforceCallerIdentity is the regression test for
// TC-9989DDB0: GET /api/get-all-objects, /api/get-all-actions, and
// /api/get-all-roles trusted a caller-supplied userId query parameter
// verbatim whenever it was non-empty, with no check that it matched the
// caller's own session identity or that the caller had any admin
// relationship to the target's organization -- so a fully unauthenticated
// caller (or an authenticated caller from an unrelated organization) could
// read any user's granted Casbin objects/actions/roles just by supplying
// that user's id.
//
// Invariant under test: nobody -- least of all an unauthenticated caller,
// and no authenticated caller outside the target's own organization -- may
// read another user's granted objects/actions/roles via the userId query
// parameter. Self-lookups, same-organization admin lookups, and global
// admin lookups must keep working (positive controls).
func TestGetAllEndpointsEnforceCallerIdentity(t *testing.T) {
	object.InitConfig()

	victimOrg := "tc9989ddb0-org"
	otherOrg := "tc9989ddb0-other-org"

	victimId := seedAuthzTestUser(t, victimOrg, "victim", false)
	sameOrgAdminId := seedAuthzTestUser(t, victimOrg, "org-admin", true)
	otherOrgUserId := seedAuthzTestUser(t, otherOrg, "mallory", false)
	otherOrgAdminId := seedAuthzTestUser(t, otherOrg, "other-org-admin", true)
	globalAdminId := seedAuthzTestUser(t, "built-in", "tc9989ddb0-global-admin", false)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	secretResource, secretRole := seedAuthzTestEntitlement(t, victimOrg, victimId, suffix)

	type endpoint struct {
		name       string
		methodName string
		call       func(c *ApiController)
		secret     string // value that must appear in a *successful* response's data
	}
	endpoints := []endpoint{
		{
			name:       "get-all-objects",
			methodName: "GetAllObjects",
			call:       func(c *ApiController) { c.GetAllObjects() },
			secret:     secretResource,
		},
		{
			name:       "get-all-roles",
			methodName: "GetAllRoles",
			call:       func(c *ApiController) { c.GetAllRoles() },
			secret:     secretRole,
		},
		{
			name:       "get-all-actions",
			methodName: "GetAllActions",
			call:       func(c *ApiController) { c.GetAllActions() },
			secret:     "", // Read/Write are shared verbs; asserted via status only, see below
		},
	}

	for _, ep := range endpoints {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			// --- Positive control: victim reading their own data (no
			// userId param) must keep working, proving the environment is
			// healthy and the fix doesn't regress self-service access. ---
			t.Run("control: authenticated self-lookup still works", func(t *testing.T) {
				c := newAuthzTestApiController("/api/"+ep.name, ep.methodName, victimId)
				ep.call(c)
				resp, ok := c.Data["json"].(*Response)
				if !ok || resp.Status != "ok" {
					t.Fatalf("baseline broken: victim could not read their own data: %#v", c.Data["json"])
				}
				if ep.secret != "" && !dataContainsString(resp.Data, ep.secret) {
					t.Fatalf("victim's own self-lookup did not contain the seeded secret %q: %#v", ep.secret, resp.Data)
				}
			})

			// --- Positive control: a same-organization admin may look up
			// the victim explicitly via userId. ---
			t.Run("control: same-org admin can still look up another user", func(t *testing.T) {
				c := newAuthzTestApiController("/api/"+ep.name+"?userId="+victimId, ep.methodName, sameOrgAdminId)
				ep.call(c)
				resp, ok := c.Data["json"].(*Response)
				if !ok || resp.Status != "ok" {
					t.Fatalf("same-org admin lookup failed: %#v", c.Data["json"])
				}
				if ep.secret != "" && !dataContainsString(resp.Data, ep.secret) {
					t.Fatalf("same-org admin lookup did not contain the seeded secret %q: %#v", ep.secret, resp.Data)
				}
			})

			// --- Positive control: a global admin may look up the victim. ---
			t.Run("control: global admin can still look up another user", func(t *testing.T) {
				c := newAuthzTestApiController("/api/"+ep.name+"?userId="+victimId, ep.methodName, globalAdminId)
				ep.call(c)
				resp, ok := c.Data["json"].(*Response)
				if !ok || resp.Status != "ok" {
					t.Fatalf("global admin lookup failed: %#v", c.Data["json"])
				}
				if ep.secret != "" && !dataContainsString(resp.Data, ep.secret) {
					t.Fatalf("global admin lookup did not contain the seeded secret %q: %#v", ep.secret, resp.Data)
				}
			})

			// --- Vulnerable case 1: a fully unauthenticated caller (no
			// session at all -- currentUserId left empty) supplies the
			// victim's userId. ---
			t.Run("unauthenticated caller cannot look up another user", func(t *testing.T) {
				c := newAuthzTestApiController("/api/"+ep.name+"?userId="+victimId, ep.methodName, "")
				ep.call(c)
				resp, ok := c.Data["json"].(*Response)
				if !ok {
					t.Fatalf("unexpected response type: %#v", c.Data["json"])
				}
				if resp.Status == "ok" {
					t.Fatalf("VULNERABLE: an unauthenticated caller (no session) read %s's data via userId. body=%#v", victimId, resp)
				}
				if ep.secret != "" && dataContainsString(resp.Data, ep.secret) {
					t.Fatalf("VULNERABLE: an unauthenticated caller's response leaked the seeded secret %q", ep.secret)
				}
			})

			// --- Control: an unauthenticated caller with no userId param
			// either must keep being rejected the same way it already was
			// before this fix. ---
			t.Run("control: unauthenticated caller with no userId is still rejected", func(t *testing.T) {
				c := newAuthzTestApiController("/api/"+ep.name, ep.methodName, "")
				ep.call(c)
				resp, ok := c.Data["json"].(*Response)
				if !ok {
					t.Fatalf("unexpected response type: %#v", c.Data["json"])
				}
				if resp.Status == "ok" {
					t.Fatalf("VULNERABLE (regression): an unauthenticated caller with no userId got a successful response: %#v", resp)
				}
			})

			// --- Vulnerable case 2: an authenticated caller from an
			// unrelated organization, with no admin relationship to the
			// victim's organization, supplies the victim's userId. ---
			t.Run("authenticated non-owner cannot look up another user", func(t *testing.T) {
				c := newAuthzTestApiController("/api/"+ep.name+"?userId="+victimId, ep.methodName, otherOrgUserId)
				ep.call(c)
				resp, ok := c.Data["json"].(*Response)
				if !ok {
					t.Fatalf("unexpected response type: %#v", c.Data["json"])
				}
				if resp.Status == "ok" {
					t.Fatalf("VULNERABLE: an unrelated authenticated caller (%s) read %s's data via userId. body=%#v", otherOrgUserId, victimId, resp)
				}
				if ep.secret != "" && dataContainsString(resp.Data, ep.secret) {
					t.Fatalf("VULNERABLE: an unrelated authenticated caller's response leaked the seeded secret %q", ep.secret)
				}
			})

			// --- Vulnerable case 3: an admin of a *different* organization
			// (not the victim's) supplies the victim's userId. Admin status
			// alone must not be enough -- it must be admin status over the
			// *target's* organization. ---
			t.Run("admin of a different organization cannot look up the victim", func(t *testing.T) {
				c := newAuthzTestApiController("/api/"+ep.name+"?userId="+victimId, ep.methodName, otherOrgAdminId)
				ep.call(c)
				resp, ok := c.Data["json"].(*Response)
				if !ok {
					t.Fatalf("unexpected response type: %#v", c.Data["json"])
				}
				if resp.Status == "ok" {
					t.Fatalf("VULNERABLE: an admin of an unrelated organization (%s) read %s's data via userId. body=%#v", otherOrgAdminId, victimId, resp)
				}
				if ep.secret != "" && dataContainsString(resp.Data, ep.secret) {
					t.Fatalf("VULNERABLE: a different-organization admin's response leaked the seeded secret %q", ep.secret)
				}
			})
		})
	}
}
