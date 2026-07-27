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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	_ "unsafe"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestGetSubscriptionRequiresAuthenticatedOwner(t *testing.T) {
	setupSubscriptionTestStore(t)

	subscription := &object.Subscription{
		Owner:       "test-org",
		Name:        "private-subscription",
		DisplayName: "Private subscription",
		User:        "alice",
		Pricing:     "private-tier",
		StartTime:   "2026-07-01T00:00:00Z",
		EndTime:     "2027-07-01T00:00:00Z",
		Period:      "P1Y",
		State:       object.SubStateActive,
	}
	if ok, err := object.AddSubscription(subscription); err != nil || !ok {
		t.Fatalf("AddSubscription() ok=%v, err=%v", ok, err)
	}

	authorized := callGetSubscription(t, subscription.GetId(), "test-org/alice")
	if authorized.Status != "ok" {
		t.Fatalf("authorized owner status = %q, msg = %q", authorized.Status, authorized.Msg)
	}
	if got := responseDataString(t, authorized, "user"); got != "alice" {
		t.Fatalf("authorized owner got user %q, want alice", got)
	}

	nonOwner := callGetSubscription(t, subscription.GetId(), "test-org/bob")
	if nonOwner.Status == "ok" && responseDataString(t, nonOwner, "user") == "alice" {
		t.Fatalf("non-owner caller read private subscription: %#v", nonOwner.Data)
	}

	admin := callGetSubscription(t, subscription.GetId(), "built-in/admin")
	if admin.Status != "ok" {
		t.Fatalf("global admin status = %q, msg = %q", admin.Status, admin.Msg)
	}
	if got := responseDataString(t, admin, "user"); got != "alice" {
		t.Fatalf("global admin got user %q, want alice", got)
	}

	unauthenticated := callGetSubscription(t, subscription.GetId(), "")
	if unauthenticated.Status == "ok" && responseDataString(t, unauthenticated, "user") == "alice" {
		t.Fatalf("unauthenticated caller read private subscription: %#v", unauthenticated.Data)
	}
}

func setupSubscriptionTestStore(t *testing.T) {
	t.Helper()

	adapter, err := object.NewAdapter("sqlite", ":memory:", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		adapter.Engine.Close()
	})

	setObjectOrmer(t, adapter)
	if err := adapter.Engine.Sync2(new(object.Organization), new(object.User), new(object.ThirdPartyLink), new(object.Subscription)); err != nil {
		t.Fatal(err)
	}

	if _, err := adapter.Engine.Insert(&object.Organization{Owner: "admin", Name: "test-org"}); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	if _, err := adapter.Engine.Insert(&object.User{Owner: "test-org", Name: "alice"}); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := adapter.Engine.Insert(&object.User{Owner: "test-org", Name: "bob"}); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := adapter.Engine.Insert(&object.User{Owner: "built-in", Name: "admin"}); err != nil {
		t.Fatalf("insert admin: %v", err)
	}
}

func callGetSubscription(t *testing.T, id string, sessionUser string) responseBody {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/get-subscription?id="+url.QueryEscape(id), nil)
	recorder := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.SetData("currentUserId", sessionUser)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "GetSubscription", controller)
	controller.GetSubscription()

	var resp responseBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v; body=%s", err, recorder.Body.String())
	}
	return resp
}

type responseBody struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Data   any    `json:"data"`
}

func responseDataString(t *testing.T, resp responseBody, key string) string {
	t.Helper()

	data, ok := resp.Data.(map[string]any)
	if !ok {
		return ""
	}
	value, _ := data[key].(string)
	return value
}

//go:linkname objectOrmer github.com/casdoor/casdoor/object.ormer
var objectOrmer *object.Ormer

func setObjectOrmer(t *testing.T, adapter *object.Ormer) {
	t.Helper()

	previous := objectOrmer
	objectOrmer = adapter
	t.Cleanup(func() {
		objectOrmer = previous
	})
}
