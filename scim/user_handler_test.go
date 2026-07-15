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

package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
)

// setupScopedTestUser creates a disposable organization, application, and
// user (mirroring what an admin would do via the regular API) so the SCIM
// org-scoping invariant can be exercised without touching any pre-existing
// data. It returns the created user (with its SCIM id populated) and a
// cleanup func.
func setupScopedTestUser(t *testing.T, label string) (*object.User, func()) {
	t.Helper()
	object.InitConfig()
	object.InitUserManager()

	ts := time.Now().UnixNano()
	orgName := fmt.Sprintf("scim-scope-test-%s-%d", label, ts)
	appName := fmt.Sprintf("scim-scope-app-%s-%d", label, ts)
	userName := fmt.Sprintf("scim-scope-user-%s-%d", label, ts)

	org := &object.Organization{
		Owner:        "admin",
		Name:         orgName,
		DisplayName:  orgName,
		WebsiteUrl:   "https://example.com",
		PasswordType: "plain",
	}
	ok, err := object.AddOrganization(org)
	if err != nil {
		t.Fatalf("failed to create test organization %s: %v", orgName, err)
	}
	if !ok {
		t.Fatalf("failed to create test organization %s: not affected", orgName)
	}

	app := &object.Application{
		Owner:          "admin",
		Name:           appName,
		DisplayName:    appName,
		Organization:   orgName,
		EnablePassword: true,
		EnableSignUp:   true,
	}
	ok, err = object.AddApplication(app)
	if err != nil {
		t.Fatalf("failed to create test application %s: %v", appName, err)
	}
	if !ok {
		t.Fatalf("failed to create test application %s: not affected", appName)
	}

	user := &object.User{
		Owner:       orgName,
		Name:        userName,
		DisplayName: "Original-" + userName,
		Email:       userName + "@example.com",
		Password:    "Throwaway-Test-Pw1!",
		Type:        "normal-user",
	}
	affected, err := object.AddUser(user, "en")
	if err != nil {
		t.Fatalf("failed to create test user %s: %v", userName, err)
	}
	if !affected {
		t.Fatalf("failed to create test user %s: not affected", userName)
	}
	if user.Id == "" {
		t.Fatalf("created test user %s has no SCIM id", userName)
	}

	cleanup := func() {
		_, _ = object.DeleteUser(user)
		_, _ = object.DeleteApplication(app)
		_, _ = object.DeleteOrganization(org)
	}
	return user, cleanup
}

// doScimRequest drives scim.Server directly -- the same handler
// controllers.HandleScim dispatches to -- with the given caller org scope on
// the request context, exactly as controllers.HandleScim now does via
// WithOrgScope. An empty orgScope models a global admin (instance-wide
// access); a non-empty orgScope models an org-scoped admin.
func doScimRequest(t *testing.T, method, target, body, orgScope string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req = req.WithContext(WithOrgScope(context.Background(), orgScope))
	rr := httptest.NewRecorder()
	Server.ServeHTTP(rr, req)
	return rr
}

// TestScimUserHandlersEnforceOrgScope reproduces TC-D368FE6C: an org-scoped
// admin (IsAdmin=true in their own org only) must only be able to view and
// manage user accounts belonging to their own organization through SCIM,
// never another organization's accounts.
func TestScimUserHandlersEnforceOrgScope(t *testing.T) {
	userA, cleanupA := setupScopedTestUser(t, "a")
	defer cleanupA()
	userB, cleanupB := setupScopedTestUser(t, "b")
	defer cleanupB()

	// Control: a global admin (empty scope) can still reach both users --
	// proves the environment itself is healthy and the scoping below is
	// specific to org-scoped admins, not a broken harness.
	t.Run("global admin control can reach both orgs", func(t *testing.T) {
		for _, u := range []*object.User{userA, userB} {
			rr := doScimRequest(t, "GET", "/Users/"+u.Id, "", "")
			if rr.Code != 200 {
				t.Fatalf("global admin GET /Users/%s = %d, want 200 (environment unhealthy): %s", u.Id, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("GetAll is scoped to the caller's own org", func(t *testing.T) {
		rr := doScimRequest(t, "GET", "/Users", "", userA.Owner)
		if rr.Code != 200 {
			t.Fatalf("GET /Users as org-scoped admin = %d, want 200: %s", rr.Code, rr.Body.String())
		}

		var listResp struct {
			Resources []struct {
				UserName string `json:"userName"`
			} `json:"Resources"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
			t.Fatalf("could not parse SCIM ListResponse: %v body=%s", err, rr.Body.String())
		}

		sawOwnUser := false
		for _, res := range listResp.Resources {
			if res.UserName == userB.Name {
				t.Fatalf("SCIM invariant violated: org-scoped admin for org %q saw foreign-org user %q via GET /Users", userA.Owner, userB.Name)
			}
			if res.UserName == userA.Name {
				sawOwnUser = true
			}
		}
		if !sawOwnUser {
			t.Fatalf("org-scoped admin for org %q did not see their own user %q via GET /Users (broken environment)", userA.Owner, userA.Name)
		}
	})

	t.Run("GET a foreign-org user is denied", func(t *testing.T) {
		rr := doScimRequest(t, "GET", "/Users/"+userB.Id, "", userA.Owner)
		if rr.Code == 200 {
			t.Fatalf("SCIM invariant violated: org-scoped admin for org %q could GET foreign-org user %q (id=%s) via SCIM: %s", userA.Owner, userB.Name, userB.Id, rr.Body.String())
		}
	})

	t.Run("GET the caller's own-org user is allowed (control)", func(t *testing.T) {
		rr := doScimRequest(t, "GET", "/Users/"+userA.Id, "", userA.Owner)
		if rr.Code != 200 {
			t.Fatalf("org-scoped admin could not GET their own user (broken environment): %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("PATCH to a foreign-org user is denied and does not persist", func(t *testing.T) {
		body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"SCIM-TEST-PROOF"}]}`
		rr := doScimRequest(t, "PATCH", "/Users/"+userB.Id, body, userA.Owner)
		if rr.Code == 200 {
			t.Fatalf("SCIM invariant violated: org-scoped admin for org %q could PATCH foreign-org user %q (id=%s) via SCIM: %s", userA.Owner, userB.Name, userB.Id, rr.Body.String())
		}

		reloaded, err := object.GetUserByUserIdOnly(userB.Id)
		if err != nil {
			t.Fatal(err)
		}
		if reloaded == nil {
			t.Fatal("foreign-org user disappeared after denied PATCH")
		}
		if reloaded.DisplayName == "SCIM-TEST-PROOF" {
			t.Fatalf("write leaked through despite denial: foreign-org user's displayName was changed to %q", reloaded.DisplayName)
		}
	})

	t.Run("PATCH to the caller's own-org user is allowed (control)", func(t *testing.T) {
		body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"SCIM-TEST-OK"}]}`
		rr := doScimRequest(t, "PATCH", "/Users/"+userA.Id, body, userA.Owner)
		if rr.Code != 200 {
			t.Fatalf("org-scoped admin could not PATCH their own user (broken environment): %d %s", rr.Code, rr.Body.String())
		}

		reloaded, err := object.GetUserByUserIdOnly(userA.Id)
		if err != nil {
			t.Fatal(err)
		}
		if reloaded == nil || reloaded.DisplayName != "SCIM-TEST-OK" {
			t.Fatalf("legitimate PATCH did not persist as expected: %+v", reloaded)
		}
	})
}
