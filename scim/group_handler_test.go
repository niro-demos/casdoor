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

package scim

// Same root cause as user_handler_test.go (controllers.HandleScim discarding
// the caller's own organization) also left scim/group_handler.go's Get,
// GetAll, and Create unscoped -- an org-scoped SCIM admin could read a
// group belonging to a different organization, list every organization's
// groups, or provision a new group into an organization other than their
// own. These tests cover the group-resource analog of the user-resource
// invariant.

import (
	"testing"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	scimlib "github.com/elimity-com/scim"
)

// seedCrossOrgGroupFixture creates two isolated organizations (reusing
// seedCrossOrgFixture's org+application setup) and one group in each, via
// object.AddGroup -- the project's own creation path.
func seedCrossOrgGroupFixture(t *testing.T) (groupA *object.Group, groupB *object.Group) {
	t.Helper()
	userA, userB := seedCrossOrgFixture(t)

	mkGroup := func(org, name string) *object.Group {
		g := &object.Group{
			Owner:       org,
			Name:        name,
			DisplayName: name,
			CreatedTime: util.GetCurrentTime(),
			IsTopGroup:  true,
			IsEnabled:   true,
		}
		ok, err := object.AddGroup(g)
		if err != nil || !ok {
			t.Fatalf("seed group %s/%s: ok=%v err=%v", org, name, ok, err)
		}
		t.Cleanup(func() { _, _ = object.DeleteGroup(g) })
		return g
	}

	groupA = mkGroup(userA.Owner, "group-a")
	groupB = mkGroup(userB.Owner, "group-b")
	return groupA, groupB
}

func TestGroupResourceHandlerGetDeniesCrossOrgRead(t *testing.T) {
	groupA, groupB := seedCrossOrgGroupFixture(t)
	h := GroupResourceHandler{}

	// Positive control: an org-scoped admin can read their OWN
	// organization's group.
	res, err := h.Get(requestScopedAs(t, groupA.Owner), groupA.GetId())
	if err != nil {
		t.Fatalf("positive control broke: in-org Get failed (%v) -- endpoint itself is broken, not just the org boundary", err)
	}
	if res.ID != groupA.GetId() {
		t.Fatalf("positive control broke: in-org Get returned wrong resource: got %s want %s", res.ID, groupA.GetId())
	}

	// Violation under test: the SAME org-scoped admin must be denied when
	// reading a group that belongs to a DIFFERENT organization.
	_, err = h.Get(requestScopedAs(t, groupA.Owner), groupB.GetId())
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin (owner=%q) was able to read a group (owner=%q) belonging to a different organization via SCIM GET /Groups/%s", groupA.Owner, groupB.Owner, groupB.GetId())
	}

	// A true global admin is not confined to a single organization.
	res, err = h.Get(requestScopedAs(t, ""), groupB.GetId())
	if err != nil {
		t.Fatalf("global admin Get of an any-org group should succeed: %v", err)
	}
	if res.ID != groupB.GetId() {
		t.Fatalf("global admin Get returned wrong resource: got %s want %s", res.ID, groupB.GetId())
	}
}

func TestGroupResourceHandlerGetAllScopesToCallerOrg(t *testing.T) {
	groupA, groupB := seedCrossOrgGroupFixture(t)
	h := GroupResourceHandler{}

	page, err := h.GetAll(requestScopedAs(t, groupA.Owner), scimlib.ListRequestParams{StartIndex: 1, Count: 100})
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}

	sawOwnOrgGroup := false
	for _, res := range page.Resources {
		if res.ID == groupB.GetId() {
			t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin (owner=%q) listing via SCIM GET /Groups included a group (owner=%q) from a DIFFERENT organization", groupA.Owner, groupB.Owner)
		}
		if res.ID == groupA.GetId() {
			sawOwnOrgGroup = true
		}
	}
	if !sawOwnOrgGroup {
		t.Fatalf("positive control broke: org-scoped admin's listing did not include their OWN organization's group -- endpoint itself is broken, not just the boundary")
	}
}

func TestGroupResourceHandlerCreateForcesCallerOrg(t *testing.T) {
	groupA, groupB := seedCrossOrgGroupFixture(t)
	h := GroupResourceHandler{}

	attrs := scimlib.ResourceAttributes{
		"displayName": "org-admin-created-group",
		// getAttrJson (scim/util.go) only recognizes a raw
		// map[string]interface{} here -- the same shape the SCIM library
		// produces when it unmarshals a real JSON request body -- not the
		// named scim.ResourceAttributes type, so build it as a plain map.
		GroupExtensionKey: map[string]interface{}{
			// An org-scoped admin (owner == groupA.Owner) attempts to
			// provision a new group directly into a DIFFERENT organization.
			"organization": groupB.Owner,
		},
	}

	res, err := h.Create(requestScopedAs(t, groupA.Owner), attrs)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	created, err := object.GetGroup(res.ID)
	if err != nil {
		t.Fatalf("reloading created group: %v", err)
	}
	if created == nil {
		t.Fatalf("created group not found by id %s", res.ID)
	}
	t.Cleanup(func() { _, _ = object.DeleteGroup(created) })

	if created.Owner != groupA.Owner {
		t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin (owner=%q) provisioned a group into a DIFFERENT organization (owner=%q) via SCIM POST /Groups", groupA.Owner, created.Owner)
	}
}
