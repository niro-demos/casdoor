// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

// Regression tests for two provider/upload-resource security invariants:
//
//   - TC-617A1123: an organization-scoped admin (IsAdmin==true, Owner !=
//     "built-in") must not be able to unmask the secrets of the shared,
//     platform-wide provider pool (Owner=="admin") via
//     GET /api/get-providers?withSecret=1, even though that pool always
//     rides along with her own org's listing (object.GetProviders ORs in
//     owner=="admin").
//   - TC-5DFADE92: POST /api/upload-resource must reject a caller who is
//     not signed in -- even when the request supplies a `provider` query
//     param -- and, once signed in, must reject a caller who is neither an
//     admin nor the owner of the owner/user the upload targets.
//
// These tests drive the real ApiController methods (no HTTP server, no
// mocked auth) against an isolated, throwaway sqlite database, following
// the same object.InitConfig()-style bootstrap already used by
// object/*_test.go and deployment/deploy_test.go, just pointed at a private
// sqlite file instead of the shared dev MySQL database in conf/app.conf so
// these tests can never collide with real data or with other test runs.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

const secTestRealSecret = "SUPER-SECRET-SHARED-VALUE-regression-test"

// TestMain bootstraps one throwaway sqlite database for every test in this
// package, and tears it down afterwards. It mirrors object.InitConfig()
// (InitAdapter + CreateTables), plus object.InitDb() to get the built-in
// org/admin/application/cert that AddUser/AddApplication/AddProvider
// require, but targets a private temp file instead of conf/app.conf's
// shared MySQL database.
func TestMain(m *testing.M) {
	os.Exit(runControllersTests(m))
}

func runControllersTests(m *testing.M) int {
	tempDir, err := os.MkdirTemp("", "casdoor-controllers-test-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)
	defer os.RemoveAll("files") // written by the "Local File System" storage provider, relative to cwd

	dbFile := filepath.Join(tempDir, "casdoor_controllers_test.db")
	os.Setenv("driverName", "sqlite")
	os.Setenv("dataSourceName", fmt.Sprintf("file:%s?cache=shared", dbFile))
	os.Setenv("dbName", "casdoor")
	os.Setenv("isDemoMode", "false")

	// object.InitFlag() registers -createDatabase/-config/etc flags and
	// parses them from os.Args; give it a controlled argv (pointing -config
	// at the real conf/app.conf, same relative path object.InitConfig()
	// uses from a one-level-deep package) instead of `go test`'s own flags,
	// then restore os.Args so the rest of the test binary behaves normally.
	// -createDatabase intentionally stays at its default (false): sqlite
	// has no "CREATE DATABASE" statement, and the sqlite file above is
	// already created on first open.
	oldArgs := os.Args
	os.Args = []string{oldArgs[0], "-config=../conf/app.conf"}
	object.InitFlag()
	os.Args = oldArgs
	// object.InitFlag()'s flag.Parse() call above consumed our restricted
	// argv, so `go test`'s own flags (-test.v, -test.run, ...) were never
	// parsed into the testing package's state; re-parse now against the
	// restored, real os.Args so `go test -v` etc. still behave normally.
	flag.Parse()

	object.InitAdapter()
	object.CreateTables()
	object.InitDb()

	return m.Run()
}

// secTestFixtures holds the throwaway org/app/users/providers these tests
// exercise. Built once per test function (each with a unique org name) so
// the avatar-mutation assertions in one test can't be polluted by another.
type secTestFixtures struct {
	orgName         string
	sharedProvider  *object.Provider // Owner=="admin": the shared, platform-wide pool
	storageProvider *object.Provider // Owner=="admin", Category=="Storage": used by upload-resource
	orgAdmin        *object.User     // Owner==orgName, IsAdmin==true -- NOT a global admin
	victim          *object.User     // Owner==orgName, IsAdmin==false
	attacker        *object.User     // Owner==orgName, IsAdmin==false, a different principal than victim
}

func setupSecTestFixtures(t *testing.T, suffix string) *secTestFixtures {
	t.Helper()

	orgName := "sec-test-org-" + suffix
	appName := "sec-test-app-" + suffix

	ok, err := object.AddOrganization(&object.Organization{
		Owner:        "admin",
		Name:         orgName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "Security Test Org " + suffix,
		PasswordType: "plain",
		InitScore:    2000,
	})
	if err != nil || !ok {
		t.Fatalf("failed to create test organization: ok=%v err=%v", ok, err)
	}

	ok, err = object.AddApplication(&object.Application{
		Owner:          "admin",
		Name:           appName,
		CreatedTime:    util.GetCurrentTime(),
		DisplayName:    "Security Test App " + suffix,
		Organization:   orgName,
		Cert:           "cert-built-in",
		EnablePassword: true,
	})
	if err != nil || !ok {
		t.Fatalf("failed to create test application: ok=%v err=%v", ok, err)
	}

	orgAdmin := &object.User{
		Owner:             orgName,
		Name:              "org-admin-" + suffix,
		CreatedTime:       util.GetCurrentTime(),
		Type:              "normal-user",
		Password:          "OrgAdmin-Test-Pw1!",
		DisplayName:       "Org Admin",
		Email:             "org-admin-" + suffix + "@example.com",
		IsAdmin:           true,
		SignupApplication: appName,
	}
	if ok, err := object.AddUser(orgAdmin, "en"); err != nil || !ok {
		t.Fatalf("failed to create org-admin test user: ok=%v err=%v", ok, err)
	}

	victim := &object.User{
		Owner:             orgName,
		Name:              "victim-" + suffix,
		CreatedTime:       util.GetCurrentTime(),
		Type:              "normal-user",
		Password:          "Victim-Test-Pw1!",
		DisplayName:       "Victim",
		Email:             "victim-" + suffix + "@example.com",
		IsAdmin:           false,
		SignupApplication: appName,
	}
	if ok, err := object.AddUser(victim, "en"); err != nil || !ok {
		t.Fatalf("failed to create victim test user: ok=%v err=%v", ok, err)
	}

	attacker := &object.User{
		Owner:             orgName,
		Name:              "attacker-" + suffix,
		CreatedTime:       util.GetCurrentTime(),
		Type:              "normal-user",
		Password:          "Attacker-Test-Pw1!",
		DisplayName:       "Attacker",
		Email:             "attacker-" + suffix + "@example.com",
		IsAdmin:           false,
		SignupApplication: appName,
	}
	if ok, err := object.AddUser(attacker, "en"); err != nil || !ok {
		t.Fatalf("failed to create attacker test user: ok=%v err=%v", ok, err)
	}

	sharedProvider := &object.Provider{
		Owner:        "admin",
		Name:         "sec-test-shared-provider-" + suffix,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "Security Test Shared Provider",
		Category:     "Notification",
		Type:         "Custom",
		ClientId:     "sec-test-client-id",
		ClientSecret: secTestRealSecret,
	}
	if ok, err := object.AddProvider(sharedProvider); err != nil || !ok {
		t.Fatalf("failed to create shared test provider: ok=%v err=%v", ok, err)
	}

	storageProvider := &object.Provider{
		Owner:       "admin",
		Name:        "sec-test-storage-provider-" + suffix,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Security Test Storage Provider",
		Category:    "Storage",
		Type:        object.ProviderTypeLocalFileSystem,
	}
	if ok, err := object.AddProvider(storageProvider); err != nil || !ok {
		t.Fatalf("failed to create storage test provider: ok=%v err=%v", ok, err)
	}

	return &secTestFixtures{
		orgName:         orgName,
		sharedProvider:  sharedProvider,
		storageProvider: storageProvider,
		orgAdmin:        orgAdmin,
		victim:          victim,
		attacker:        attacker,
	}
}

// testApiResp mirrors controllers.Response but keeps Data as raw JSON so
// each test can decode it into whatever shape it expects.
type testApiResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
	Data2  json.RawMessage `json:"data2"`
}

// newTestController builds a real *ApiController wired to an in-memory
// httptest request/response pair, with currentUserId stashed into the
// beego context exactly as routers/authz_filter.go's ApiFilter does for a
// real HTTP request -- currentUserId=="" reproduces an anonymous
// (unauthenticated) caller.
func newTestController(t *testing.T, method, target string, body []byte, contentType, currentUserId string) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()

	var reqBody *bytes.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, reqBody)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "", nil)
	c.Ctx.Input.SetData("currentUserId", currentUserId)

	return c, w
}

func decodeTestResp(t *testing.T, w *httptest.ResponseRecorder) testApiResp {
	t.Helper()
	var resp testApiResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not decode response body %q: %v", w.Body.String(), err)
	}
	return resp
}

func decodeProviderList(t *testing.T, data json.RawMessage) []*object.Provider {
	t.Helper()
	var providers []*object.Provider
	if err := json.Unmarshal(data, &providers); err != nil {
		t.Fatalf("could not decode provider list %q: %v", string(data), err)
	}
	return providers
}

func findProviderByName(providers []*object.Provider, name string) *object.Provider {
	for _, p := range providers {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func buildMultipartUpload(t *testing.T, filename string, content []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("could not build multipart body: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("could not write multipart body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("could not close multipart writer: %v", err)
	}
	return buf.Bytes(), w.FormDataContentType()
}

// TestOrgAdminCannotUnmaskSharedProviderSecret is the regression test for
// TC-617A1123.
//
// Invariant: an organization-scoped admin (IsAdmin==true but Owner !=
// "built-in") must never receive the real (unmasked) clientSecret of a
// provider in the shared, platform-wide pool (Owner=="admin") via
// GET /api/get-providers?withSecret=1, even though object.GetProviders
// always ORs that pool into every org's own listing.
func TestOrgAdminCannotUnmaskSharedProviderSecret(t *testing.T) {
	fx := setupSecTestFixtures(t, "mask")

	target := fmt.Sprintf("/api/get-providers?owner=%s&withSecret=1", fx.orgName)

	// Positive control: the true global admin, with withSecret=1, DOES see
	// the real secret -- proves the masking machinery and fixtures here are
	// healthy, so a failure below is specifically the org-admin boundary,
	// not a broken test environment.
	gc, gw := newTestController(t, http.MethodGet, target, nil, "", "built-in/admin")
	gc.GetProviders()
	gResp := decodeTestResp(t, gw)
	if gResp.Status != "ok" {
		t.Fatalf("FATAL(environment): global admin listing failed: %+v", gResp)
	}
	gProvider := findProviderByName(decodeProviderList(t, gResp.Data), fx.sharedProvider.Name)
	if gProvider == nil {
		t.Fatalf("FATAL(environment): global admin did not see the shared-pool provider in the org listing")
	}
	if gProvider.ClientSecret != secTestRealSecret {
		t.Fatalf("FATAL(environment): global admin withSecret=1 did not receive the real secret, got %q -- masking mechanism itself is broken", gProvider.ClientSecret)
	}

	// Invariant under test: the org-scoped (non-global) admin must not
	// receive the shared pool's real secret.
	oc, ow := newTestController(t, http.MethodGet, target, nil, "", util.GetId(fx.orgName, fx.orgAdmin.Name))
	oc.GetProviders()
	oResp := decodeTestResp(t, ow)

	if oResp.Status == "ok" {
		oProvider := findProviderByName(decodeProviderList(t, oResp.Data), fx.sharedProvider.Name)
		if oProvider != nil && oProvider.ClientSecret == secTestRealSecret {
			t.Fatalf("VULNERABLE: org-scoped admin (not a global admin) received the UNMASKED real secret of the shared platform-wide-pool provider: %+v", oProvider)
		}
	}
	// A rejected request (oResp.Status == "error") also satisfies the
	// invariant: the secret was never returned either way.
}

// TestUploadResourceRequiresAuthAndOwnership is the regression test for
// TC-5DFADE92.
//
// Invariant: nobody can use /api/upload-resource to write another user's
// avatar unless they are signed in AND (an admin for that org OR the
// target user themselves) -- specifically, supplying a `provider` query
// param must not let an anonymous caller skip the login gate, and being
// signed in as some other, unprivileged user must not be enough either.
func TestUploadResourceRequiresAuthAndOwnership(t *testing.T) {
	fx := setupSecTestFixtures(t, "upload")

	baseTarget := fmt.Sprintf("/api/upload-resource?owner=%s&user=%s&application=%s&tag=avatar&provider=%s",
		fx.orgName, fx.victim.Name, "sec-test-app-upload", fx.storageProvider.Name)

	originalAvatar := fx.victim.Avatar

	assertVictimAvatarUnchanged := func(when string) {
		t.Helper()
		refreshed, err := object.GetUserNoCheck(fx.victim.GetId())
		if err != nil {
			t.Fatalf("could not re-fetch victim user %s: %v", when, err)
		}
		if refreshed == nil {
			t.Fatalf("victim user disappeared %s", when)
		}
		if refreshed.Avatar != originalAvatar {
			t.Fatalf("VULNERABLE: victim's avatar changed %s: got %q, want unchanged %q", when, refreshed.Avatar, originalAvatar)
		}
	}

	// --- Case 1: an anonymous (no session) caller must be rejected, even
	// though she supplied a valid `provider` query param naming a real
	// storage provider. This is the exact bypass TC-5DFADE92 exploited:
	// GetProviderFromContext used to resolve `provider` and return before
	// RequireSignedIn() ever ran. ---
	body1, ct1 := buildMultipartUpload(t, "evil1.png", []byte("attacker bytes 1"))
	ac, aw := newTestController(t, http.MethodPost, baseTarget+"&fullFilePath=evil1.png", body1, ct1, "")
	ac.UploadResource()
	aResp := decodeTestResp(t, aw)
	if aResp.Status == "ok" {
		t.Fatalf("VULNERABLE: an unauthenticated caller (no session) uploaded a file and got: %+v", aResp)
	}
	assertVictimAvatarUnchanged("after the anonymous upload attempt")

	// --- Case 2: a signed-in but unprivileged caller (attacker, a
	// different acme-org user, not an admin) must not be able to overwrite
	// the VICTIM's avatar either. ---
	body2, ct2 := buildMultipartUpload(t, "evil2.png", []byte("attacker bytes 2"))
	nc, nw := newTestController(t, http.MethodPost, baseTarget+"&fullFilePath=evil2.png", body2, ct2, util.GetId(fx.orgName, fx.attacker.Name))
	nc.UploadResource()
	nResp := decodeTestResp(t, nw)
	if nResp.Status == "ok" {
		t.Fatalf("VULNERABLE: a signed-in non-owner (attacker) overwrote another user's (victim's) avatar and got: %+v", nResp)
	}
	assertVictimAvatarUnchanged("after the signed-in non-owner upload attempt")

	// --- Positive control: the victim uploading her OWN avatar must still
	// succeed -- proves the fix didn't also break the legitimate case. ---
	body3, ct3 := buildMultipartUpload(t, "own.png", []byte("victims own bytes"))
	sc, sw := newTestController(t, http.MethodPost, baseTarget+"&fullFilePath=own.png", body3, ct3, util.GetId(fx.orgName, fx.victim.Name))
	sc.UploadResource()
	sResp := decodeTestResp(t, sw)
	if sResp.Status != "ok" {
		t.Fatalf("positive control failed: the victim could not upload her own avatar: %+v", sResp)
	}
	refreshed, err := object.GetUserNoCheck(fx.victim.GetId())
	if err != nil {
		t.Fatalf("could not re-fetch victim user after her own legitimate upload: %v", err)
	}
	if refreshed == nil || refreshed.Avatar == originalAvatar || refreshed.Avatar == "" {
		t.Fatalf("positive control failed: victim's own avatar upload did not take effect, got %+v", refreshed)
	}
}
