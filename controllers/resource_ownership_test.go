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
	"testing"

	beegoCtx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// newResourceTestApiController builds an ApiController wired to a real (but
// fabricated) Beego context/request, exactly like ApiFilter does at runtime
// (it stashes the authenticated user id into ctx.Input.SetData("currentUserId",
// ...)) - so the controller method under test runs its real authorization
// logic, not a mock.
func newResourceTestApiController(t *testing.T, method, target, sessionUserId string) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()

	ctx := beegoCtx.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "", nil)

	if sessionUserId != "" {
		ctx.Input.SetData("currentUserId", sessionUserId)
	}

	return c, w
}

func decodeResourceControllerResponse(t *testing.T, w *httptest.ResponseRecorder) *Response {
	t.Helper()

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode controller response %q: %v", w.Body.String(), err)
	}
	return &resp
}

// TestGetResourcesEnforcesOwnershipCheck is the regression test for
// TC-76D56A5D: GET /api/get-resources is missing the ownership check that
// its sibling GET /api/get-resource enforces, letting a standard user list
// another user's resources in a different org (or their own org) purely by
// passing that user's owner/user in the query string.
//
// Invariant: a standard user must not be able to list another user's
// uploaded file/resource records that they do not own or administer.
func TestGetResourcesEnforcesOwnershipCheck(t *testing.T) {
	object.InitConfig()
	object.InitUserManager()

	suffix := util.GenerateId()
	victimOrg := "resource-authz-victim-" + suffix
	attackerOrg := "resource-authz-attacker-" + suffix
	victimName := "alice-" + suffix
	attackerName := "bob-" + suffix

	victim := &object.User{Owner: victimOrg, Name: victimName, Id: util.GenerateId()}
	if ok, err := object.AddUsers([]*object.User{victim}); err != nil || !ok {
		t.Fatalf("failed to seed victim user: ok=%v err=%v", ok, err)
	}
	defer object.DeleteUser(victim)

	attacker := &object.User{Owner: attackerOrg, Name: attackerName, Id: util.GenerateId()}
	if ok, err := object.AddUsers([]*object.User{attacker}); err != nil || !ok {
		t.Fatalf("failed to seed attacker user: ok=%v err=%v", ok, err)
	}
	defer object.DeleteUser(attacker)

	sameOrgBystander := &object.User{Owner: victimOrg, Name: "carol-" + suffix, Id: util.GenerateId()}
	if ok, err := object.AddUsers([]*object.User{sameOrgBystander}); err != nil || !ok {
		t.Fatalf("failed to seed same-org bystander user: ok=%v err=%v", ok, err)
	}
	defer object.DeleteUser(sameOrgBystander)

	victimResource := &object.Resource{Owner: victimOrg, Name: "victim-resource-" + suffix, User: victimName, Url: "https://storage.example.com/secret/" + suffix}
	if _, err := object.AddOrUpdateResource(victimResource); err != nil {
		t.Fatalf("failed to seed victim resource: %v", err)
	}
	defer object.DeleteResource(victimResource)

	attackerSessionUserId := attackerOrg + "/" + attackerName
	bystanderSessionUserId := victimOrg + "/" + sameOrgBystander.Name
	victimSessionUserId := victimOrg + "/" + victimName

	t.Run("cross-org standard user must not list another org's resources", func(t *testing.T) {
		c, w := newResourceTestApiController(t, "GET", "/api/get-resources?owner="+victimOrg+"&user="+victimName, attackerSessionUserId)
		c.GetResources()
		resp := decodeResourceControllerResponse(t, w)
		if resp.Status == "ok" {
			t.Fatalf("invariant violated: attacker (%s) listed %s/%s's resources: %s", attackerSessionUserId, victimOrg, victimName, w.Body.String())
		}
	})

	t.Run("same-org standard user must not list another user's resources", func(t *testing.T) {
		c, w := newResourceTestApiController(t, "GET", "/api/get-resources?owner="+victimOrg+"&user="+victimName, bystanderSessionUserId)
		c.GetResources()
		resp := decodeResourceControllerResponse(t, w)
		if resp.Status == "ok" {
			t.Fatalf("invariant violated: same-org bystander (%s) listed %s/%s's resources: %s", bystanderSessionUserId, victimOrg, victimName, w.Body.String())
		}
	})

	// Control: the victim listing their OWN resources must keep working -
	// proves the fix denies cross-user access without breaking the
	// legitimate self-read path.
	t.Run("control: user can still list their own resources", func(t *testing.T) {
		c, w := newResourceTestApiController(t, "GET", "/api/get-resources?owner="+victimOrg+"&user="+victimName, victimSessionUserId)
		c.GetResources()
		resp := decodeResourceControllerResponse(t, w)
		if resp.Status != "ok" {
			t.Fatalf("self-read was unexpectedly denied: %s", w.Body.String())
		}

		var resources []*object.Resource
		dataBytes, err := json.Marshal(resp.Data)
		if err != nil {
			t.Fatalf("failed to marshal resp.Data: %v", err)
		}
		if err := json.Unmarshal(dataBytes, &resources); err != nil {
			t.Fatalf("failed to decode resources: %v", err)
		}
		found := false
		for _, r := range resources {
			if r.Owner == victimOrg && r.Name == victimResource.Name {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected self-read to return the seeded resource, got: %s", w.Body.String())
		}
	})
}
