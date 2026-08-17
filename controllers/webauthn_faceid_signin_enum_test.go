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
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// signinEnumTestSetup boots just enough of the app (config + DB connection)
// for ApiController methods to be invoked directly, bypassing the HTTP
// router/filters -- the same style of DB-backed setup used by the object
// package's own tests (see object/user_test.go, which calls
// object.InitConfig() directly against a real database).
var signinEnumTestSetup sync.Once

func initSigninEnumTest(t *testing.T) {
	t.Helper()

	signinEnumTestSetup.Do(func() {
		object.InitConfig()
		object.InitUserManager()
	})
}

// setupSigninEnumOrg creates an organization plus one application for it (an
// application is required before any user can be added to a non-built-in
// organization), and registers cleanup.
func setupSigninEnumOrg(t *testing.T, orgName string) {
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

	app := &object.Application{
		Owner:        "admin",
		Name:         "app-" + orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "app-" + orgName,
		Organization: orgName,
	}
	ok, err = object.AddApplication(app)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture application for %s: ok=%v err=%v", orgName, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })
}

// callSigninBegin drives WebAuthnSigninBegin/FaceIDSigninBegin directly --
// the same seam the vulnerability lived in -- by simulating an unauthenticated
// GET to the given path with owner/name query params.
func callSigninBegin(t *testing.T, path, owner, name string) *Response {
	t.Helper()

	target := fmt.Sprintf("http://example.com%s?%s", path, url.Values{
		"owner": {owner},
		"name":  {name},
	}.Encode())

	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "SigninBegin", nil)

	switch path {
	case "/api/webauthn/signin/begin":
		c.WebAuthnSigninBegin()
	case "/api/faceid-signin-begin":
		c.FaceIDSigninBegin()
	default:
		t.Fatalf("unknown path %q", path)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), err)
	}
	return &resp
}

// TestWebAuthnFaceIDSigninBeginDoesNotLeakUserExistence is the regression
// test for TC-367B572B.
//
// Invariant under test: an unauthenticated pre-login endpoint that checks
// whether a user has a passwordless factor enrolled must not reveal whether
// the given username exists at all -- "no such user" and "user exists but
// has no enrolled factor" must produce the exact same client-visible
// message. Before the fix, WebAuthnSigninBegin/FaceIDSigninBegin returned a
// distinct, existence-confirming message ("Found no credentials for this
// user" / "Face data does not exist, cannot log in") for a real user with no
// enrolled credential, letting an unauthenticated caller enumerate valid
// usernames per organization.
func TestWebAuthnFaceIDSigninBeginDoesNotLeakUserExistence(t *testing.T) {
	initSigninEnumTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "signin-enum-it-" + suffix
	setupSigninEnumOrg(t, orgName)

	// bob: a real account with neither a WebAuthn credential nor a Face ID
	// enrolled.
	bob := &object.User{
		Owner:       orgName,
		Name:        "bob",
		Id:          orgName + "/bob",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "bob",
	}
	ok, err := object.AddUser(bob, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user bob: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(bob) })

	nonexistent1 := "zzz_no_such_user_1_" + suffix
	nonexistent2 := "zzz_no_such_user_2_" + suffix

	paths := []string{"/api/webauthn/signin/begin", "/api/faceid-signin-begin"}

	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			resp1 := callSigninBegin(t, path, orgName, nonexistent1)
			resp2 := callSigninBegin(t, path, orgName, nonexistent2)
			respBob := callSigninBegin(t, path, orgName, "bob")

			// normalize strips the request-specific owner/name substring out
			// of a message so two messages that share the same TEMPLATE
			// (e.g. "The user: %s/%s doesn't exist") but differ only in the
			// echoed identifier compare as equal -- mirroring the PoC's own
			// normalization (niro/findings/TC-367B572B/poc.go).
			normalize := func(msg, name string) string {
				return strings.ReplaceAll(msg, orgName+"/"+name, "<id>")
			}
			norm1 := normalize(resp1.Msg, nonexistent1)
			norm2 := normalize(resp2.Msg, nonexistent2)
			normBob := normalize(respBob.Msg, "bob")

			// Positive control: two different nonexistent usernames must
			// produce the exact same message template -- proves the
			// endpoint's response shape is stable and the comparison below
			// isn't just noise.
			if resp1.Status != "error" || resp2.Status != "error" {
				t.Fatalf("control failed: nonexistent users did not error: resp1=%+v resp2=%+v", resp1, resp2)
			}
			if norm1 != norm2 {
				t.Fatalf("control failed: two nonexistent users produced different message templates (%q vs %q) -- environment looks unhealthy, not a clean invariant check", norm1, norm2)
			}

			if respBob.Status != "error" {
				t.Fatalf("expected an error response for bob (real user, no credential enrolled), got: %+v", respBob)
			}

			// The invariant: a real user with no enrolled factor must be
			// indistinguishable from a nonexistent user.
			if normBob != norm1 {
				t.Fatalf("username existence leak on %s: real user with no credential got message %q, distinct from the nonexistent-user message %q",
					path, respBob.Msg, resp1.Msg)
			}
		})
	}
}

// TestFaceIDSigninBeginStillWorksForEnrolledUser is a legitimate-path
// control: a real user who *has* enrolled Face ID data must still receive a
// successful response, proving the enumeration fix collapses only the two
// error paths and doesn't turn the endpoint into an unconditional failure.
func TestFaceIDSigninBeginStillWorksForEnrolledUser(t *testing.T) {
	initSigninEnumTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "signin-enum-ok-" + suffix
	setupSigninEnumOrg(t, orgName)

	alice := &object.User{
		Owner:       orgName,
		Name:        "alice",
		Id:          orgName + "/alice",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "alice",
		FaceIds: []*object.FaceId{
			{Name: "primary", FaceIdData: []float64{0.1, 0.2, 0.3}},
		},
	}
	ok, err := object.AddUser(alice, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user alice: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(alice) })

	resp := callSigninBegin(t, "/api/faceid-signin-begin", orgName, "alice")
	if resp.Status != "ok" {
		t.Fatalf("control failed: enrolled user alice could not begin Face ID signin: %+v", resp)
	}
}
