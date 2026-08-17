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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// callGetSubscription drives (*ApiController).GetSubscription() in-process,
// the same way a live HTTP request does, but without opening a real socket
// or session cookie. GetSessionUsername() checks
// ctx.Input.GetData("currentUserId") first, which is exactly what
// routers.ApiFilter stashes there for every real request -- including an
// empty string for an anonymous caller with no cookie / no Authorization
// header at all. Mirroring that here exercises the real, unmodified
// controller method end to end without depending on beego's session store,
// which is not initialized in this in-process harness.
func callGetSubscription(t *testing.T, signedInUserId, id string) (status string, msg string, body []byte) {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/api/get-subscription?id="+id, nil)
	w := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(w, r)
	ctx.Input.SetData("currentUserId", signedInUserId)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetSubscription", nil)
	c.GetSubscription()

	body = w.Body.Bytes()
	var parsed Response
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("GetSubscription did not return valid JSON: %v (body=%s)", err, body)
	}
	return parsed.Status, parsed.Msg, body
}

// TestGetSubscriptionEnforcesOwnership is a regression test for TC-1D92A74D:
// GetSubscription() called object.GetSubscription(id) and returned the
// record directly with no ownership/admin check at all, unlike the sibling
// handlers GetOrder and GetPayment in the same package, which both gate on
// IsAdmin() plus a session-owner match before responding. That let any
// caller -- a different user in the same tenant, a user in a completely
// different tenant, or a fully unauthenticated visitor with no session at
// all -- read another user's subscription record (plan, pricing, period,
// start/end time, state) just by knowing or guessing its owner/name id.
//
// Fixtures are created directly through the object package's own factories
// (mirroring the same tenant/user/subscription shape the PoC exercised: a
// same-tenant non-owner and an unauthenticated caller), not read from
// Niro's ephemeral harness credentials, so this test is self-contained and
// reproducible against any freshly booted instance with its own database.
func TestGetSubscriptionEnforcesOwnership(t *testing.T) {
	object.InitConfig()
	object.InitDb()
	object.InitUserManager()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	testOrg := "niro-regress-org-" + suffix
	otherUserName := "niro-regress-other-" + suffix
	victimUserName := "niro-regress-victim-" + suffix
	victimSubName := "niro-regress-sub-" + suffix

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

	testApp := "niro-regress-app-" + suffix
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
		Name:        victimUserName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     false,
	}
	if _, err := object.AddUser(victimUser, "en"); err != nil {
		t.Fatalf("harness problem: could not create victim test user: %v", err)
	}
	defer object.DeleteUser(victimUser)

	otherUser := &object.User{
		Owner:       testOrg,
		Name:        otherUserName,
		Id:          util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		IsAdmin:     false,
	}
	if _, err := object.AddUser(otherUser, "en"); err != nil {
		t.Fatalf("harness problem: could not create second test user: %v", err)
	}
	defer object.DeleteUser(otherUser)

	victimSubscription := &object.Subscription{
		Owner:       testOrg,
		Name:        victimSubName,
		DisplayName: "niro-regress TC-1D92A74D victim subscription",
		CreatedTime: util.GetCurrentTime(),
		User:        victimUserName,
		StartTime:   "2026-01-01T00:00:00Z",
		EndTime:     "2030-01-01T00:00:00Z",
		Period:      "Monthly",
		State:       object.SubStateActive,
	}
	if ok, err := object.AddSubscription(victimSubscription); err != nil || !ok {
		t.Fatalf("harness problem: could not create victim subscription: ok=%v err=%v", ok, err)
	}
	defer object.DeleteSubscription(victimSubscription)

	subId := testOrg + "/" + victimSubName

	t.Run("anonymous caller (no session at all) cannot read another user's subscription", func(t *testing.T) {
		status, msg, body := callGetSubscription(t, "", subId)
		if status == "ok" {
			t.Fatalf("invariant violated: a fully unauthenticated caller (no cookie, no Authorization header) read subscription %s -- billing data leak. body=%s", subId, body)
		}
		t.Logf("denied as expected: status=%s msg=%s", status, msg)
	})

	t.Run("different non-admin user in the same tenant cannot read another user's subscription", func(t *testing.T) {
		status, msg, body := callGetSubscription(t, testOrg+"/"+otherUserName, subId)
		if status == "ok" {
			t.Fatalf("invariant violated: standard user %s/%s read %s's subscription -- cross-user leak. body=%s", testOrg, otherUserName, victimUserName, body)
		}
		t.Logf("denied as expected: status=%s msg=%s", status, msg)
	})

	t.Run("control: the subscription's own owner can still read it", func(t *testing.T) {
		status, msg, body := callGetSubscription(t, testOrg+"/"+victimUserName, subId)
		if status != "ok" {
			t.Fatalf("harness problem: subscription owner %s/%s could not read their own subscription (status=%s msg=%s) -- the fix over-restricted legitimate access. body=%s", testOrg, victimUserName, status, msg, body)
		}
	})

	t.Run("control: global admin can still read any subscription", func(t *testing.T) {
		status, msg, body := callGetSubscription(t, "built-in/admin", subId)
		if status != "ok" {
			t.Fatalf("harness problem: global admin (built-in/admin) could not read %s's subscription (status=%s msg=%s) -- the fix over-restricted legitimate global-admin access. body=%s", subId, status, msg, body)
		}
	})
}
