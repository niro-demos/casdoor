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
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// This file is the regression suite for one shared root cause covering four
// findings: object.UpdatePermission, object.UpdateServer, object.UpdateAgent,
// object.UpdateEntry and object.UpdateEnforcer all persisted the request
// body's Owner field verbatim via an AllCols()/full-struct update, with no
// check comparing it to the existing record's Owner for non-global-admin
// callers. That let an org-scoped admin, authorized only because the URL
// "id" query param names an object they own, relocate the row into another
// organization's namespace (including "built-in") by putting a different
// "owner" in the request body.
//
// Invariant under test, for each object type: an organization admin editing
// a record they own must not be able to move it into a different
// organization by supplying a mismatched "owner" in the update body.

// newOwnerGuardTestController builds a minimal, fully wired ApiController
// for a POST request carrying a JSON body, with the signed-in user set the
// way the real production auth filter sets it (routers/authz_filter.go
// calls ctx.Input.SetData("currentUserId", username)), so
// GetSessionUsername()/IsAdmin()/IsGlobalAdmin() resolve without needing a
// real HTTP session/cookie stack.
func newOwnerGuardTestController(rawURL string, body interface{}, currentUserId string) *ApiController {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}

	req := httptest.NewRequest("POST", rawURL, strings.NewReader(string(bodyBytes)))
	w := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(w, req)
	ctx.Input.RequestBody = bodyBytes

	c := &ApiController{}
	c.Init(ctx, "ApiController", "", nil)
	if currentUserId != "" {
		c.Ctx.Input.SetData("currentUserId", currentUserId)
	}
	return c
}

func ownerGuardSeedOrganization(t *testing.T, name string) {
	t.Helper()
	existing, err := object.GetOrganization("admin/" + name)
	if err != nil {
		t.Fatalf("failed to check for existing test organization %s: %v", name, err)
	}
	if existing != nil {
		return
	}

	org := &object.Organization{
		Owner: "admin",
		Name:  name,
	}
	affected, err := object.AddOrganization(org)
	if err != nil || !affected {
		t.Fatalf("failed to seed test organization %s: affected=%v err=%v", name, affected, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteOrganization(org)
	})
}

func ownerGuardSeedOrgAdmin(t *testing.T, owner, name string) {
	t.Helper()
	existing, err := object.GetUser(owner + "/" + name)
	if err != nil {
		t.Fatalf("failed to check for existing test user %s/%s: %v", owner, name, err)
	}
	if existing != nil {
		return
	}

	user := &object.User{
		Owner:   owner,
		Name:    name,
		Id:      owner + "-" + name + "-tc-owner-guard",
		IsAdmin: true,
	}
	// AddUsers() is the syncer/batch-upload insert path: unlike AddUser(), it
	// skips the "built-in" org signup guard, so it can seed either org used
	// by these tests with a plain admin row.
	affected, err := object.AddUsers([]*object.User{user})
	if err != nil || !affected {
		t.Fatalf("failed to seed test org admin %s/%s: affected=%v err=%v", owner, name, affected, err)
	}
}

func TestUpdatePermissionRejectsCrossOrgOwnerChange(t *testing.T) {
	object.InitConfig()

	victimOrg := "tc40ecb832-victim-org"
	otherOrg := "tc40ecb832-other-org"
	ownerGuardSeedOrganization(t, victimOrg)
	ownerGuardSeedOrganization(t, otherOrg)
	ownerGuardSeedOrgAdmin(t, victimOrg, "org-admin")

	permName := "tc40ecb832-perm"
	permission := &object.Permission{
		Owner:        victimOrg,
		Name:         permName,
		Users:        []string{victimOrg + "/org-admin"},
		ResourceType: "Application",
		Resources:    []string{"res-a"},
		Actions:      []string{"Read"},
		Effect:       "Allow",
		IsEnabled:    true,
	}
	_, _ = object.DeletePermission(permission)
	if _, err := object.AddPermission(permission); err != nil {
		t.Fatalf("failed to seed test permission: %v", err)
	}
	t.Cleanup(func() {
		_, _ = object.DeletePermission(permission)
	})

	adminSession := victimOrg + "/org-admin"
	id := victimOrg + "/" + permName

	// --- Vulnerable case: org-admin moves the permission they own into a
	// different organization by setting a mismatched "owner" in the body. ---
	body := map[string]interface{}{
		"owner":        otherOrg,
		"name":         permName,
		"users":        []string{otherOrg + "/admin"},
		"resourceType": "Application",
		"resources":    []string{"pwned-resource"},
		"actions":      []string{"Read", "Write", "Admin"},
		"effect":       "Allow",
		"isEnabled":    true,
	}
	c := newOwnerGuardTestController("/api/update-permission?id="+id, body, adminSession)
	c.UpdatePermission()
	// Registered unconditionally (before inspecting the response) so a
	// vulnerable run that actually relocates the row still cleans it up,
	// rather than leaking state that would corrupt a later test run.
	t.Cleanup(func() {
		if m, _ := object.GetPermission(otherOrg + "/" + permName); m != nil {
			_, _ = object.DeletePermission(m)
		}
	})
	resp, ok := c.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", c.Data["json"])
	}
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: org-admin moved a permission they own into org %q via body owner mismatch: %#v", otherOrg, resp)
	}

	moved, err := object.GetPermission(otherOrg + "/" + permName)
	if err != nil {
		t.Fatalf("GetPermission for %s failed: %v", otherOrg+"/"+permName, err)
	}
	if moved != nil {
		t.Fatalf("VULNERABLE: permission row was persisted under org %q", otherOrg)
	}

	// --- Control: the same org-admin can still legitimately update the
	// permission without changing its owner. ---
	legitBody := map[string]interface{}{
		"owner":        victimOrg,
		"name":         permName,
		"users":        []string{victimOrg + "/org-admin"},
		"resourceType": "Application",
		"resources":    []string{"res-a-updated"},
		"actions":      []string{"Read"},
		"effect":       "Allow",
		"isEnabled":    true,
	}
	legit := newOwnerGuardTestController("/api/update-permission?id="+id, legitBody, adminSession)
	legit.UpdatePermission()
	legitResp, ok := legit.Data["json"].(*Response)
	if !ok || legitResp.Status != "ok" {
		t.Fatalf("baseline broken: org-admin could not update their own permission: %#v", legit.Data["json"])
	}
}

func TestUpdateServerRejectsCrossOrgOwnerChange(t *testing.T) {
	object.InitConfig()

	victimOrg := "tc54201159-victim-org-srv"
	otherOrg := "tc54201159-other-org-srv"
	ownerGuardSeedOrganization(t, victimOrg)
	ownerGuardSeedOrganization(t, otherOrg)
	ownerGuardSeedOrgAdmin(t, victimOrg, "org-admin")

	name := "tc54201159-server"
	server := &object.Server{
		Owner:       victimOrg,
		Name:        name,
		DisplayName: "Test server",
		Url:         "http://example.com/",
	}
	_, _ = object.DeleteServer(server)
	if _, err := object.AddServer(server); err != nil {
		t.Fatalf("failed to seed test server: %v", err)
	}
	t.Cleanup(func() { _, _ = object.DeleteServer(server) })

	adminSession := victimOrg + "/org-admin"
	id := victimOrg + "/" + name

	body := map[string]interface{}{
		"owner":       otherOrg,
		"name":        name,
		"displayName": "pwned server",
		"url":         "http://example.com/",
	}
	c := newOwnerGuardTestController("/api/update-server?id="+id, body, adminSession)
	c.UpdateServer()
	t.Cleanup(func() {
		if m, _ := object.GetServer(otherOrg + "/" + name); m != nil {
			_, _ = object.DeleteServer(m)
		}
	})
	resp, ok := c.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", c.Data["json"])
	}
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: org-admin moved a server they own into org %q via body owner mismatch: %#v", otherOrg, resp)
	}

	moved, err := object.GetServer(otherOrg + "/" + name)
	if err != nil {
		t.Fatalf("GetServer for %s failed: %v", otherOrg+"/"+name, err)
	}
	if moved != nil {
		t.Fatalf("VULNERABLE: server row was persisted under org %q", otherOrg)
	}

	legitBody := map[string]interface{}{
		"owner":       victimOrg,
		"name":        name,
		"displayName": "legit rename",
		"url":         "http://example.com/",
	}
	legit := newOwnerGuardTestController("/api/update-server?id="+id, legitBody, adminSession)
	legit.UpdateServer()
	legitResp, ok := legit.Data["json"].(*Response)
	if !ok || legitResp.Status != "ok" {
		t.Fatalf("baseline broken: org-admin could not update their own server: %#v", legit.Data["json"])
	}
}

func TestUpdateAgentRejectsCrossOrgOwnerChange(t *testing.T) {
	object.InitConfig()

	victimOrg := "tc54201159-victim-org-agt"
	otherOrg := "tc54201159-other-org-agt"
	ownerGuardSeedOrganization(t, victimOrg)
	ownerGuardSeedOrganization(t, otherOrg)
	ownerGuardSeedOrgAdmin(t, victimOrg, "org-admin")

	name := "tc54201159-agent"
	agent := &object.Agent{
		Owner:       victimOrg,
		Name:        name,
		DisplayName: "Test agent",
		Url:         "http://example.com/",
	}
	_, _ = object.DeleteAgent(agent)
	if _, err := object.AddAgent(agent); err != nil {
		t.Fatalf("failed to seed test agent: %v", err)
	}
	t.Cleanup(func() { _, _ = object.DeleteAgent(agent) })

	adminSession := victimOrg + "/org-admin"
	id := victimOrg + "/" + name

	body := map[string]interface{}{
		"owner":       otherOrg,
		"name":        name,
		"displayName": "pwned agent",
		"url":         "http://example.com/",
	}
	c := newOwnerGuardTestController("/api/update-agent?id="+id, body, adminSession)
	c.UpdateAgent()
	t.Cleanup(func() {
		if m, _ := object.GetAgent(otherOrg + "/" + name); m != nil {
			_, _ = object.DeleteAgent(m)
		}
	})
	resp, ok := c.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", c.Data["json"])
	}
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: org-admin moved an agent they own into org %q via body owner mismatch: %#v", otherOrg, resp)
	}

	moved, err := object.GetAgent(otherOrg + "/" + name)
	if err != nil {
		t.Fatalf("GetAgent for %s failed: %v", otherOrg+"/"+name, err)
	}
	if moved != nil {
		t.Fatalf("VULNERABLE: agent row was persisted under org %q", otherOrg)
	}

	legitBody := map[string]interface{}{
		"owner":       victimOrg,
		"name":        name,
		"displayName": "legit rename",
		"url":         "http://example.com/",
	}
	legit := newOwnerGuardTestController("/api/update-agent?id="+id, legitBody, adminSession)
	legit.UpdateAgent()
	legitResp, ok := legit.Data["json"].(*Response)
	if !ok || legitResp.Status != "ok" {
		t.Fatalf("baseline broken: org-admin could not update their own agent: %#v", legit.Data["json"])
	}
}

func TestUpdateEntryRejectsCrossOrgOwnerChange(t *testing.T) {
	object.InitConfig()

	victimOrg := "tc54201159-victim-org-ent"
	otherOrg := "tc54201159-other-org-ent"
	ownerGuardSeedOrganization(t, victimOrg)
	ownerGuardSeedOrganization(t, otherOrg)
	ownerGuardSeedOrgAdmin(t, victimOrg, "org-admin")

	name := "tc54201159-entry"
	entry := &object.Entry{
		Owner:       victimOrg,
		Name:        name,
		DisplayName: "Test entry",
	}
	_, _ = object.DeleteEntry(entry)
	if _, err := object.AddEntry(entry); err != nil {
		t.Fatalf("failed to seed test entry: %v", err)
	}
	t.Cleanup(func() { _, _ = object.DeleteEntry(entry) })

	adminSession := victimOrg + "/org-admin"
	id := victimOrg + "/" + name

	body := map[string]interface{}{
		"owner":       otherOrg,
		"name":        name,
		"displayName": "pwned entry",
	}
	c := newOwnerGuardTestController("/api/update-entry?id="+id, body, adminSession)
	c.UpdateEntry()
	t.Cleanup(func() {
		if m, _ := object.GetEntry(otherOrg + "/" + name); m != nil {
			_, _ = object.DeleteEntry(m)
		}
	})
	resp, ok := c.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", c.Data["json"])
	}
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: org-admin moved an entry they own into org %q via body owner mismatch: %#v", otherOrg, resp)
	}

	moved, err := object.GetEntry(otherOrg + "/" + name)
	if err != nil {
		t.Fatalf("GetEntry for %s failed: %v", otherOrg+"/"+name, err)
	}
	if moved != nil {
		t.Fatalf("VULNERABLE: entry row was persisted under org %q", otherOrg)
	}

	legitBody := map[string]interface{}{
		"owner":       victimOrg,
		"name":        name,
		"displayName": "legit rename",
	}
	legit := newOwnerGuardTestController("/api/update-entry?id="+id, legitBody, adminSession)
	legit.UpdateEntry()
	legitResp, ok := legit.Data["json"].(*Response)
	if !ok || legitResp.Status != "ok" {
		t.Fatalf("baseline broken: org-admin could not update their own entry: %#v", legit.Data["json"])
	}
}

func TestUpdateEnforcerRejectsCrossOrgOwnerChange(t *testing.T) {
	object.InitConfig()

	victimOrg := "tcb7f4df71-victim-org"
	otherOrg := "tcb7f4df71-other-org"
	ownerGuardSeedOrganization(t, victimOrg)
	ownerGuardSeedOrganization(t, otherOrg)
	ownerGuardSeedOrgAdmin(t, victimOrg, "org-admin")

	name := "tcb7f4df71-enforcer"
	enforcer := &object.Enforcer{
		Owner:       victimOrg,
		Name:        name,
		DisplayName: name,
	}
	_, _ = object.DeleteEnforcer(enforcer)
	if _, err := object.AddEnforcer(enforcer); err != nil {
		t.Fatalf("failed to seed test enforcer: %v", err)
	}
	t.Cleanup(func() { _, _ = object.DeleteEnforcer(enforcer) })

	adminSession := victimOrg + "/org-admin"
	id := victimOrg + "/" + name

	body := map[string]interface{}{
		"owner":       otherOrg,
		"name":        name,
		"displayName": "pwned enforcer",
	}
	c := newOwnerGuardTestController("/api/update-enforcer?id="+id, body, adminSession)
	c.UpdateEnforcer()
	t.Cleanup(func() {
		if m, _ := object.GetEnforcer(otherOrg + "/" + name); m != nil {
			_, _ = object.DeleteEnforcer(m)
		}
	})
	resp, ok := c.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", c.Data["json"])
	}
	if resp.Status == "ok" {
		t.Fatalf("VULNERABLE: org-admin moved an enforcer they own into org %q via body owner mismatch: %#v", otherOrg, resp)
	}

	moved, err := object.GetEnforcer(otherOrg + "/" + name)
	if err != nil {
		t.Fatalf("GetEnforcer for %s failed: %v", otherOrg+"/"+name, err)
	}
	if moved != nil {
		t.Cleanup(func() { _, _ = object.DeleteEnforcer(moved) })
		t.Fatalf("VULNERABLE: enforcer row was persisted under org %q", otherOrg)
	}

	legitBody := map[string]interface{}{
		"owner":       victimOrg,
		"name":        name,
		"displayName": "legit rename",
	}
	legit := newOwnerGuardTestController("/api/update-enforcer?id="+id, legitBody, adminSession)
	legit.UpdateEnforcer()
	legitResp, ok := legit.Data["json"].(*Response)
	if !ok || legitResp.Status != "ok" {
		t.Fatalf("baseline broken: org-admin could not update their own enforcer: %#v", legit.Data["json"])
	}
}

// TestUpdatePermissionGlobalAdminCanStillMoveAcrossOrgs is a positive control
// proving the fix does not regress the legitimate global-admin workflow: a
// true global admin (owner=="built-in") must still be able to move a
// permission across organizations, exactly like object.UpdateRole already
// allows for roles.
func TestUpdatePermissionGlobalAdminCanStillMoveAcrossOrgs(t *testing.T) {
	object.InitConfig()

	victimOrg := "tc40ecb832-ga-victim-org"
	otherOrg := "tc40ecb832-ga-other-org"
	ownerGuardSeedOrganization(t, victimOrg)
	ownerGuardSeedOrganization(t, otherOrg)

	globalAdminId := "built-in-tc40ecb832-ga-admin-tc-owner-guard"
	existingAdmin, err := object.GetUser("built-in/tc40ecb832-ga-admin")
	if err != nil {
		t.Fatalf("failed to check for existing global admin: %v", err)
	}
	if existingAdmin == nil {
		globalAdmin := &object.User{
			Owner: "built-in",
			Name:  "tc40ecb832-ga-admin",
			Id:    globalAdminId,
		}
		affected, err := object.AddUsers([]*object.User{globalAdmin})
		if err != nil || !affected {
			t.Fatalf("failed to seed global admin: affected=%v err=%v", affected, err)
		}
	}

	permName := "tc40ecb832-ga-perm"
	permission := &object.Permission{
		Owner:        victimOrg,
		Name:         permName,
		ResourceType: "Application",
		Resources:    []string{"res-a"},
		Actions:      []string{"Read"},
		Effect:       "Allow",
		IsEnabled:    true,
	}
	_, _ = object.DeletePermission(permission)
	if _, err := object.AddPermission(permission); err != nil {
		t.Fatalf("failed to seed test permission: %v", err)
	}

	globalAdminSession := "built-in/tc40ecb832-ga-admin"
	id := victimOrg + "/" + permName

	body := map[string]interface{}{
		"owner":        otherOrg,
		"name":         permName,
		"resourceType": "Application",
		"resources":    []string{"res-a"},
		"actions":      []string{"Read"},
		"effect":       "Allow",
		"isEnabled":    true,
	}
	c := newOwnerGuardTestController("/api/update-permission?id="+id, body, globalAdminSession)
	c.UpdatePermission()
	resp, ok := c.Data["json"].(*Response)
	if !ok || resp.Status != "ok" {
		t.Fatalf("REGRESSION: a true global admin could not move a permission across organizations (existing UpdateRole-style admin workflow broken): %#v", c.Data["json"])
	}

	moved, err := object.GetPermission(otherOrg + "/" + permName)
	if err != nil {
		t.Fatalf("GetPermission for %s failed: %v", otherOrg+"/"+permName, err)
	}
	if moved == nil {
		t.Fatalf("REGRESSION: global admin's cross-org move did not persist")
	}
	t.Cleanup(func() {
		_, _ = object.DeletePermission(moved)
	})
}
