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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// linkApiTestSetup boots just enough of the app (config + DB connection + an
// in-memory session manager) for ApiController methods to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used elsewhere for controller-level regression tests (see
// controllers/introspect_token_test.go).
var linkApiTestSetup sync.Once

func initLinkApiTest(t *testing.T) {
	t.Helper()

	linkApiTestSetup.Do(func() {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			panic("failed to resolve test file path")
		}
		repoRoot := filepath.Dir(filepath.Dir(thisFile))

		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id_test"
		web.BConfig.WebConfig.Session.SessionGCMaxLifetime = 3600

		// Loads conf/app.conf (real MySQL DSN) and registers beego's session
		// manager, mirroring what main.go does at startup.
		web.TestBeegoInit(repoRoot)

		object.InitAdapter()
		object.CreateTables()
		object.InitDb()
		object.InitUserManager()
	})
}

// setupLinkTestOrg creates an organization plus one application configured
// with a single unlinkable OAuth-type provider item (mirroring
// provider_github_test/canUnlink:true in the live target), and registers
// cleanup.
func setupLinkTestOrg(t *testing.T, orgName, providerName string) {
	t.Helper()

	org := &object.Organization{
		Owner:       "admin",
		Name:        orgName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: orgName,
	}
	ok, err := object.AddOrganization(org)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture organization %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(org) })

	provider := &object.Provider{
		Owner:       "admin",
		Name:        providerName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: providerName,
		Category:    "OAuth",
		Type:        "GitHub",
	}
	ok, err = object.AddProvider(provider)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture provider %s: ok=%v err=%v", providerName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteProvider(provider) })

	app := &object.Application{
		Owner:        "admin",
		Name:         "app-" + orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "app-" + orgName,
		Organization: orgName,
		Providers: []*object.ProviderItem{
			{
				Owner:     "admin",
				Name:      providerName,
				CanSignIn: true,
				CanUnlink: true,
			},
		},
	}
	ok, err = object.AddApplication(app)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture application for %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })
}

// setupLinkTestUser creates a standard (non-admin) user with the given
// initial GitHub-linked value and registers cleanup.
func setupLinkTestUser(t *testing.T, orgName, name, githubValue string) *object.User {
	t.Helper()

	user := &object.User{
		Owner:       orgName,
		Name:        name,
		Id:          orgName + "/" + name,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: name,
		GitHub:      githubValue,
	}
	ok, err := object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s/%s: ok=%v err=%v", orgName, name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// callUnlink drives ApiController.Unlink directly, simulating
// POST /api/unlink with a JSON body and an authenticated session -- the same
// seam the vulnerability lives in.
func callUnlink(t *testing.T, sessionUserId string, body map[string]interface{}) *Response {
	t.Helper()

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/unlink", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(w, req)
	ctx.Input.RequestBody = bodyBytes

	sess, err := web.GlobalSessions.SessionStart(w, req)
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	defer sess.SessionRelease(context.Background(), w)
	ctx.Input.CruSession = sess

	if sessionUserId != "" {
		if err := sess.Set(context.Background(), "username", sessionUserId); err != nil {
			t.Fatalf("failed to set session username: %v", err)
		}
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "Unlink", nil)
	c.Unlink()

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), err)
	}
	return &resp
}

// TestUnlinkRejectsSpoofedOwnIdCrossAccountTarget is the regression test for
// TC-8494EC5D: an authenticated standard user must not be able to unlink an
// identity provider from a different user's account by supplying their own
// real `id` while pointing `owner`/`name` at the victim. Only the account
// owner themselves, or a global admin, may unlink a provider from an
// account.
func TestUnlinkRejectsSpoofedOwnIdCrossAccountTarget(t *testing.T) {
	initLinkApiTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "link-it-" + suffix
	providerName := "provider-test-" + suffix

	setupLinkTestOrg(t, orgName, providerName)

	canary := "bob-github-canary-" + suffix
	bob := setupLinkTestUser(t, orgName, "bob", canary)
	alice := setupLinkTestUser(t, orgName, "alice", "alice-github-"+suffix)

	aliceID := alice.GetId()
	bobID := bob.GetId()

	getBobGithub := func(t *testing.T) string {
		t.Helper()
		fresh, err := object.GetUser(bobID)
		if err != nil || fresh == nil {
			t.Fatalf("failed to refetch bob: ok=%v err=%v", fresh != nil, err)
		}
		return fresh.GitHub
	}

	// Positive control: an HONEST cross-account request (id/owner/name all
	// point at bob) must be rejected -- proves normal authorization and the
	// test environment are healthy before the spoofed case is judged.
	t.Run("honest_cross_account_rejected", func(t *testing.T) {
		resp := callUnlink(t, aliceID, map[string]interface{}{
			"providerType": "github",
			"providerName": providerName,
			"user": map[string]interface{}{
				"id":     bobID,
				"owner":  orgName,
				"name":   "bob",
				"github": "placeholder-nonempty",
			},
		})
		if resp.Status == "ok" {
			t.Fatalf("control failed: honest cross-account unlink was not rejected: %+v", resp)
		}
		if got := getBobGithub(t); got != canary {
			t.Fatalf("control failed: bob's github field changed unexpectedly: got %q want %q", got, canary)
		}
	})

	// Attack / red-green case: alice spoofs `id` to her own real id (passing
	// the identity check) while pointing `owner`/`name` at bob (the field the
	// actual mutation is keyed on). Must be rejected; bob's linked account
	// must survive untouched.
	t.Run("spoofed_own_id_cross_account_target_rejected", func(t *testing.T) {
		resp := callUnlink(t, aliceID, map[string]interface{}{
			"providerType": "github",
			"providerName": providerName,
			"user": map[string]interface{}{
				"id":     aliceID,
				"owner":  orgName,
				"name":   "bob",
				"github": "placeholder-nonempty",
			},
		})

		got := getBobGithub(t)
		if resp.Status == "ok" || got != canary {
			t.Fatalf("alice (standard user, not bob, not global admin) unlinked bob's github via spoofed id: resp=%+v bob.GitHub=%q (want unchanged %q)", resp, got, canary)
		}
	})

	// Positive control: a genuine self-unlink (id/owner/name all belong to
	// the caller) must keep working -- proves the fix didn't overcorrect and
	// break legitimate self-service unlinking.
	t.Run("self_unlink_still_allowed", func(t *testing.T) {
		resp := callUnlink(t, aliceID, map[string]interface{}{
			"providerType": "github",
			"providerName": providerName,
			"user": map[string]interface{}{
				"id":     aliceID,
				"owner":  orgName,
				"name":   "alice",
				"github": "placeholder-nonempty",
			},
		})
		if resp.Status != "ok" {
			t.Fatalf("control failed: alice could not unlink her own github account: %+v", resp)
		}

		fresh, err := object.GetUser(aliceID)
		if err != nil || fresh == nil {
			t.Fatalf("failed to refetch alice: ok=%v err=%v", fresh != nil, err)
		}
		if fresh.GitHub != "" {
			t.Fatalf("control failed: alice's own github field was not cleared by her own unlink request: got %q", fresh.GitHub)
		}
	})
}
