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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/session"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

var subscriptionAuthzTestAppOnce sync.Once

// initSubscriptionAuthzTestApp brings up just enough of the real Casdoor
// beego app - config, DB adapter, session manager, and the real /api routes
// registered by routers.InitAPI() - to drive requests through the actual
// ApiController handlers, the same way the running server does. It does not
// start a TCP listener; requests are served in-process via
// web.BeeApp.Handlers.ServeHTTP.
func initSubscriptionAuthzTestApp(t *testing.T) {
	subscriptionAuthzTestAppOnce.Do(func() {
		if err := web.LoadAppConfig("ini", "../conf/app.conf"); err != nil {
			t.Fatalf("failed to load app config: %v", err)
		}
		// Mirror object.InitConfig(): sessions must be on for
		// GetSessionUsername()/IsAdmin() to behave like production.
		web.BConfig.WebConfig.Session.SessionOn = true

		object.InitAdapter()
		object.CreateTables()

		mgr, err := session.NewManager("memory", &session.ManagerConfig{
			CookieName:      "casdoor_session_id_test",
			EnableSetCookie: true,
			Gclifetime:      3600,
			CookieLifeTime:  3600,
		})
		if err != nil {
			t.Fatalf("failed to init in-memory session manager: %v", err)
		}
		web.GlobalSessions = mgr

		routers.InitAPI()
	})
}

type subscriptionAuthzApiResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

// doUnauthenticatedGet issues a GET through the real beego router with no
// cookie and no Authorization header, simulating a completely unauthenticated
// caller - exactly like the PoC's bare net/http client.
func doUnauthenticatedGet(t *testing.T, path string) (int, subscriptionAuthzApiResp) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	web.BeeApp.Handlers.ServeHTTP(w, req)

	result := w.Result()
	defer result.Body.Close()

	var out subscriptionAuthzApiResp
	if err := json.NewDecoder(result.Body).Decode(&out); err != nil {
		t.Fatalf("bad JSON response from %s: %v", path, err)
	}
	return result.StatusCode, out
}

// respHasRecord reports whether resp represents a populated ("ok" + non-null
// data) API response, i.e. a leaked record.
func respHasRecord(resp subscriptionAuthzApiResp) bool {
	return resp.Status == "ok" && len(resp.Data) > 0 && string(resp.Data) != "null"
}

// TestGetSubscriptionRejectsUnauthenticatedRead is the regression test for
// TC-6D6E4CC0.
//
// Invariant: "A user must not be able to read another user's subscription
// record by guessing or enumerating its identifier."
//
// A completely unauthenticated caller (no cookie, no Authorization header)
// must not receive a populated subscription record from
// GET /api/get-subscription, even when they know a valid id. The sibling
// GET /api/get-order endpoint - which shares the same id shape and the same
// permissive casbin rule (p, *, *, GET, /api/get-order, *) - is used as a
// live control: it must also withhold data for the same unauthenticated
// caller and the same run, proving any subscription leak is a real
// authorization gap and not a broken test environment.
func TestGetSubscriptionRejectsUnauthenticatedRead(t *testing.T) {
	initSubscriptionAuthzTestApp(t)

	owner := "niro-verify-org"
	name := fmt.Sprintf("niro-verify-sub-%d", time.Now().UnixNano())
	sub := &object.Subscription{
		Owner:       owner,
		Name:        name,
		DisplayName: "Niro Verify Sub",
		User:        "niro-verify-admin",
		StartTime:   "2026-01-01T00:00:00Z",
		EndTime:     "2027-01-01T00:00:00Z",
		State:       object.SubStateActive,
	}
	ok, err := object.AddSubscription(sub)
	if err != nil || !ok {
		t.Fatalf("failed to seed subscription fixture: ok=%v err=%v", ok, err)
	}
	defer func() {
		if _, delErr := object.DeleteSubscription(sub); delErr != nil {
			t.Logf("cleanup: failed to delete subscription fixture: %v", delErr)
		}
	}()

	id := owner + "/" + name

	// Positive control: sibling /api/get-order, same unauthenticated caller,
	// same id shape, same server/session state. This MUST withhold data;
	// if it doesn't, the environment itself is unhealthy and the
	// subscription assertion below cannot be trusted.
	orderStatusCode, orderResp := doUnauthenticatedGet(t, "/api/get-order?id="+id)
	if respHasRecord(orderResp) {
		t.Fatalf("control failed: unauthenticated GET /api/get-order (HTTP %d) unexpectedly returned data: %s -- test environment is not a healthy baseline", orderStatusCode, string(orderResp.Data))
	}

	// The finding: unauthenticated GET /api/get-subscription must not leak
	// the full subscription record.
	subStatusCode, subResp := doUnauthenticatedGet(t, "/api/get-subscription?id="+id)
	if respHasRecord(subResp) {
		t.Fatalf("VIOLATION: unauthenticated GET /api/get-subscription (HTTP %d) returned the full subscription record: %s", subStatusCode, string(subResp.Data))
	}
	if subResp.Status != "error" {
		t.Fatalf("expected an error/forbidden response for an unauthenticated subscription read, got status=%q msg=%q", subResp.Status, subResp.Msg)
	}
}
