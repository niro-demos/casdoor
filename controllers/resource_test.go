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
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// resourceApiTestSetup boots just enough of the app (config + DB connection +
// an in-memory session manager) for ApiController methods to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used by object package tests (see object/user_test.go, which calls
// object.InitConfig() directly against a real database).
var resourceApiTestSetup sync.Once

func initResourceApiTest(t *testing.T) {
	t.Helper()

	resourceApiTestSetup.Do(func() {
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

// setupResourceTestOrg creates a dedicated organization plus one application
// for it (an application is required before any user can be added to a
// non-built-in organization), and registers cleanup.
func setupResourceTestOrg(t *testing.T, orgName string) {
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

// setupResourceTestUser creates a user in orgName and registers cleanup.
func setupResourceTestUser(t *testing.T, orgName, name string, isAdmin bool) *object.User {
	t.Helper()

	user := &object.User{
		Owner:       orgName,
		Name:        name,
		Id:          orgName + "/" + name,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: name,
		IsAdmin:     isAdmin,
	}
	ok, err := object.AddUser(user, "en")
	if err != nil || !ok {
		t.Fatalf("failed to create fixture user %s/%s: ok=%v err=%v", orgName, name, ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(user) })

	return user
}

// callUploadResource drives ApiController.UploadResource directly, simulating
// POST /api/upload-resource with the given (possibly empty, meaning
// unauthenticated) session username, query string, and uploaded file body.
func callUploadResource(t *testing.T, sessionUsername, query, fileName string, fileContent []byte) (resp *Response, panicVal interface{}) {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", fileName)
	if err != nil {
		t.Fatalf("failed to build multipart file field: %v", err)
	}
	if _, err := fw.Write(fileContent); err != nil {
		t.Fatalf("failed to write multipart file content: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	target := "/api/upload-resource?" + query
	req := httptest.NewRequest(http.MethodPost, target, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)

	sess, err := web.GlobalSessions.SessionStart(rec, req)
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	defer sess.SessionRelease(context.Background(), rec)
	ctx.Input.CruSession = sess

	if sessionUsername != "" {
		if err := sess.Set(context.Background(), "username", sessionUsername); err != nil {
			t.Fatalf("failed to set session username: %v", err)
		}
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "UploadResource", nil)

	func() {
		defer func() { panicVal = recover() }()
		c.UploadResource()
	}()

	if panicVal != nil {
		return nil, panicVal
	}

	resp = &Response{}
	if err := json.Unmarshal(rec.Body.Bytes(), resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", rec.Body.String(), err)
	}
	return resp, nil
}

// TestUploadResourceRejectsUnauthenticatedAndForeignOwnership is the
// regression test for TC-D412E0D5: an unauthenticated caller could skip the
// login check on POST /api/upload-resource by supplying a `provider` query
// parameter, and the caller-supplied `owner`/`user` were never checked
// against who was actually signed in. The invariant under test: an
// unauthenticated visitor must not be able to upload files into an
// organization's resource storage or create resource records under an
// arbitrary owner/user of their choosing, and a signed-in but unrelated user
// must not be able to impersonate another user's ownership either -- while
// legitimate self-service uploads, org-admin uploads on behalf of their org,
// and trusted SDK app-account uploads keep working.
func TestUploadResourceRejectsUnauthenticatedAndForeignOwnership(t *testing.T) {
	initResourceApiTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "resource-it-" + suffix
	setupResourceTestOrg(t, orgName)

	victim := setupResourceTestUser(t, orgName, "victim", false)
	attacker := setupResourceTestUser(t, orgName, "attacker", false)
	orgAdmin := setupResourceTestUser(t, orgName, "admin", true)

	providerName := "resource-it-provider-" + suffix
	provider := &object.Provider{
		Owner:       "admin",
		Name:        providerName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: providerName,
		Category:    "Storage",
		Type:        "Local File System",
		Domain:      "http://localhost:18001",
	}
	ok, err := object.AddProvider(provider)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture storage provider: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteProvider(provider) })

	uploadDir := "resource-it-" + suffix
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("files", uploadDir)) })

	arbitraryOwner := "resource-it-arbitrary-org-" + suffix
	arbitraryUser := "resource-it-arbitrary-user-" + suffix

	cleanupOwner := func(owner string) {
		resources, err := object.GetResources(owner, "")
		if err != nil {
			return
		}
		for _, r := range resources {
			_, _ = object.DeleteResource(r)
		}
	}
	t.Cleanup(func() {
		cleanupOwner(orgName)
		cleanupOwner(arbitraryOwner)
	})

	buildQuery := func(owner, user, uniq string) string {
		vals := url.Values{}
		vals.Set("owner", owner)
		vals.Set("user", user)
		vals.Set("application", "app-"+orgName)
		vals.Set("tag", "custom")
		vals.Set("parent", "test")
		vals.Set("fullFilePath", uploadDir+"/"+uniq+".txt")
		vals.Set("provider", providerName)
		return vals.Encode()
	}

	resourceExists := func(owner, user, uniq string) bool {
		resources, err := object.GetResources(owner, user)
		if err != nil {
			t.Fatalf("failed to query resources for owner=%s user=%s: %v", owner, user, err)
		}
		for _, r := range resources {
			if strings.Contains(r.Name, uniq) {
				return true
			}
		}
		return false
	}

	// RED case (the finding): a fully unauthenticated caller must not be able
	// to upload a file and create a Resource row under an arbitrary,
	// never-authenticated owner/user of its own choosing.
	t.Run("unauthenticated_caller_with_arbitrary_owner_denied", func(t *testing.T) {
		uniq := "unauth-" + suffix
		resp, panicVal := callUploadResource(t, "", buildQuery(arbitraryOwner, arbitraryUser, uniq), "poc.txt", []byte("niro-tc-d412e0d5"))
		if panicVal != nil {
			t.Fatalf("unauthenticated upload crashed the handler: %v", panicVal)
		}
		if resp.Status == "ok" {
			t.Fatalf("unauthenticated caller successfully uploaded a resource under an arbitrary owner/user: %+v", resp)
		}
		if resourceExists(arbitraryOwner, arbitraryUser, uniq) {
			t.Fatalf("a Resource row was created under the arbitrary owner/user despite the error response")
		}
	})

	// Same root cause, authenticated variant: a signed-in but unrelated,
	// non-admin user must not be able to impersonate another user's identity
	// by supplying that user's name in the `user` query parameter.
	t.Run("authenticated_foreign_user_impersonation_denied", func(t *testing.T) {
		uniq := "impersonate-" + suffix
		resp, panicVal := callUploadResource(t, attacker.GetId(), buildQuery(orgName, victim.Name, uniq), "poc.txt", []byte("niro-tc-d412e0d5"))
		if panicVal != nil {
			t.Fatalf("impersonation attempt crashed the handler: %v", panicVal)
		}
		if resp.Status == "ok" {
			t.Fatalf("attacker successfully uploaded a resource under victim's identity: %+v", resp)
		}
		if resourceExists(orgName, victim.Name, uniq) {
			t.Fatalf("a Resource row was created under victim's identity despite the error response")
		}
	})

	// Positive control: a signed-in user uploading as themselves must keep
	// working -- proves the denials above are the missing auth/ownership
	// check, not a broken environment.
	t.Run("self_upload_allowed", func(t *testing.T) {
		uniq := "self-" + suffix
		resp, panicVal := callUploadResource(t, victim.GetId(), buildQuery(orgName, victim.Name, uniq), "self.txt", []byte("hello"))
		if panicVal != nil {
			t.Fatalf("legitimate self-upload crashed the handler: %v", panicVal)
		}
		if resp.Status != "ok" {
			t.Fatalf("control failed: victim could not upload their own resource: %+v", resp)
		}
		if !resourceExists(orgName, victim.Name, uniq) {
			t.Fatalf("control failed: no Resource row was created for victim's own legitimate upload")
		}
	})

	// Positive control: an org admin uploading on behalf of another member of
	// their own organization must keep working.
	t.Run("org_admin_upload_for_member_allowed", func(t *testing.T) {
		uniq := "admin-upload-" + suffix
		resp, panicVal := callUploadResource(t, orgAdmin.GetId(), buildQuery(orgName, victim.Name, uniq), "admin.txt", []byte("hello"))
		if panicVal != nil {
			t.Fatalf("org admin upload crashed the handler: %v", panicVal)
		}
		if resp.Status != "ok" {
			t.Fatalf("control failed: org admin could not upload a resource for a member of their own org: %+v", resp)
		}
		if !resourceExists(orgName, victim.Name, uniq) {
			t.Fatalf("control failed: no Resource row was created for the org admin's upload")
		}
	})

	// Positive control: a trusted SDK app account (Casdoor client ID &
	// secret, session username prefixed "app/") is exempt from the ownership
	// check, matching the trust level app accounts already have elsewhere in
	// this codebase (IsOrgAdmin, RequireSignedInUser). This documents and
	// locks in that deliberate scope decision.
	t.Run("app_account_upload_allowed", func(t *testing.T) {
		uniq := "app-upload-" + suffix
		resp, panicVal := callUploadResource(t, "app/app-"+orgName, buildQuery(arbitraryOwner, arbitraryUser, uniq), "app.txt", []byte("hello"))
		if panicVal != nil {
			t.Fatalf("trusted app-account upload crashed the handler: %v", panicVal)
		}
		if resp.Status != "ok" {
			t.Fatalf("control failed: trusted app account could not upload a resource: %+v", resp)
		}
		if !resourceExists(arbitraryOwner, arbitraryUser, uniq) {
			t.Fatalf("control failed: no Resource row was created for the app account's upload")
		}
	})
}
