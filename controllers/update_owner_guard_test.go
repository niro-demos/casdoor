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
	"net/url"
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

// ownerGuardTestSetup boots just enough of the app (config + DB connection +
// an in-memory session manager) for ApiController methods to be invoked
// directly, bypassing the HTTP router/filters -- the same style of DB-backed
// setup used by object package tests (see object/user_test.go, which calls
// object.InitConfig() directly against a real database).
var ownerGuardTestSetup sync.Once

func initOwnerGuardTest(t *testing.T) {
	t.Helper()

	ownerGuardTestSetup.Do(func() {
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

// setupOwnerGuardOrg creates an organization plus one application for it (an
// application is required before any user can be added to a non-built-in
// organization), and registers cleanup.
func setupOwnerGuardOrg(t *testing.T, orgName string) {
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

// setupOwnerGuardUser creates a user in orgName and registers cleanup.
func setupOwnerGuardUser(t *testing.T, orgName, name string, isAdmin bool) *object.User {
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

// Regression coverage for TC-9B51735B: a tenant org admin (a non-global-admin
// caller whose own org matches the record's current owner) must not be able
// to relocate a permission/model/adapter/enforcer record into a different
// organization by rewriting its `owner` field on update -- the same
// ownership guard UpdateRole already enforces. This drives the real
// ApiController handlers (the same seam the vulnerability lived in), rather
// than the object-layer functions directly, so the test compiles and runs
// unmodified against both the pre-fix and post-fix signatures.

const ownerGuardModelText = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`

// callUpdateWithBody drives the named ApiController update handler directly,
// simulating POST /api/<endpoint>?id=... with a JSON body, under the given
// (possibly empty, meaning unauthenticated) session username.
func callUpdateWithBody(t *testing.T, handlerName, sessionUsername, id string, body interface{}) *Response {
	t.Helper()

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	target := "/api/" + handlerName + "?id=" + url.QueryEscape(id)
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(bodyBytes))
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

	if sessionUsername != "" {
		if err := sess.Set(context.Background(), "username", sessionUsername); err != nil {
			t.Fatalf("failed to set session username: %v", err)
		}
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", handlerName, nil)

	switch handlerName {
	case "update-permission":
		c.UpdatePermission()
	case "update-model":
		c.UpdateModel()
	case "update-adapter":
		c.UpdateAdapter()
	case "update-enforcer":
		c.UpdateEnforcer()
	default:
		t.Fatalf("unknown handler %q", handlerName)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), err)
	}
	return &resp
}

// TestUpdatePermissionRejectsCrossOrgOwnerRewrite is the regression test for
// TC-9B51735B applied to permissions: the org-A tenant admin who legitimately
// owns permission org-A/perm-x must not be able to move it into org-B by
// rewriting the `owner` field in the update body.
func TestUpdatePermissionRejectsCrossOrgOwnerRewrite(t *testing.T) {
	initOwnerGuardTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := "tc9b51735b-perm-a-" + suffix
	orgB := "tc9b51735b-perm-b-" + suffix
	permName := "perm-" + suffix

	setupOwnerGuardOrg(t, orgA)
	setupOwnerGuardOrg(t, orgB)
	tenantAdmin := setupOwnerGuardUser(t, orgA, "admin", true)

	permission := &object.Permission{
		Owner:        orgA,
		Name:         permName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  permName,
		Users:        []string{tenantAdmin.GetId()},
		ResourceType: "API",
		Resources:    []string{"get-roles"},
		Actions:      []string{"GET"},
		Effect:       "Allow",
		IsEnabled:    true,
		State:        "Approved",
	}
	ok, err := object.AddPermission(permission)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture permission: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeletePermission(&object.Permission{Owner: orgA, Name: permName})
		_, _ = object.DeletePermission(&object.Permission{Owner: orgB, Name: permName})
	})

	permId := permission.GetId()

	// Exploit attempt: the org-A tenant admin rewrites owner to org-B.
	moved := &object.Permission{
		Owner:        orgB,
		Name:         permName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  permName,
		Users:        []string{tenantAdmin.GetId()},
		ResourceType: "API",
		Resources:    []string{"get-roles"},
		Actions:      []string{"GET"},
		Effect:       "Allow",
		IsEnabled:    true,
		State:        "Approved",
	}
	resp := callUpdateWithBody(t, "update-permission", tenantAdmin.GetId(), permId, moved)
	if resp.Status == "ok" {
		t.Fatalf("invariant violated: org-A tenant admin moved permission %s to org %q via update-permission (resp=%+v)", permId, orgB, resp)
	}

	stillInA, err := object.GetPermission(orgA + "/" + permName)
	if err != nil {
		t.Fatalf("GetPermission(orgA) after rejected update failed: %v", err)
	}
	if stillInA == nil {
		t.Fatalf("permission %s disappeared from org %q after a rejected owner rewrite", permId, orgA)
	}

	movedToB, err := object.GetPermission(orgB + "/" + permName)
	if err != nil {
		t.Fatalf("GetPermission(orgB) after rejected update failed: %v", err)
	}
	if movedToB != nil {
		t.Fatalf("permission was relocated into org %q despite the update being rejected", orgB)
	}

	// Positive control: the same tenant admin can still edit the permission
	// in place (no owner change).
	sameOrgUpdate := &object.Permission{
		Owner:        orgA,
		Name:         permName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  permName + "-edited",
		Users:        []string{tenantAdmin.GetId()},
		ResourceType: "API",
		Resources:    []string{"get-roles"},
		Actions:      []string{"GET"},
		Effect:       "Allow",
		IsEnabled:    true,
		State:        "Approved",
	}
	resp = callUpdateWithBody(t, "update-permission", tenantAdmin.GetId(), permId, sameOrgUpdate)
	if resp.Status != "ok" {
		t.Fatalf("legitimate same-org update by the tenant admin was rejected: %+v", resp)
	}
}

// TestUpdateModelRejectsCrossOrgOwnerRewrite mirrors the permission case for
// models.
func TestUpdateModelRejectsCrossOrgOwnerRewrite(t *testing.T) {
	initOwnerGuardTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := "tc9b51735b-model-a-" + suffix
	orgB := "tc9b51735b-model-b-" + suffix
	modelName := "model-" + suffix

	setupOwnerGuardOrg(t, orgA)
	setupOwnerGuardOrg(t, orgB)
	tenantAdmin := setupOwnerGuardUser(t, orgA, "admin", true)

	m := &object.Model{
		Owner:       orgA,
		Name:        modelName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: modelName,
		ModelText:   ownerGuardModelText,
	}
	ok, err := object.AddModel(m)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture model: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteModel(&object.Model{Owner: orgA, Name: modelName})
		_, _ = object.DeleteModel(&object.Model{Owner: orgB, Name: modelName})
	})

	modelId := m.GetId()

	moved := &object.Model{
		Owner:       orgB,
		Name:        modelName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: modelName,
		ModelText:   ownerGuardModelText,
	}
	resp := callUpdateWithBody(t, "update-model", tenantAdmin.GetId(), modelId, moved)
	if resp.Status == "ok" {
		t.Fatalf("invariant violated: org-A tenant admin moved model %s to org %q via update-model (resp=%+v)", modelId, orgB, resp)
	}

	stillInA, err := object.GetModel(orgA + "/" + modelName)
	if err != nil {
		t.Fatalf("GetModel(orgA) after rejected update failed: %v", err)
	}
	if stillInA == nil {
		t.Fatalf("model %s disappeared from org %q after a rejected owner rewrite", modelId, orgA)
	}

	movedToB, err := object.GetModel(orgB + "/" + modelName)
	if err != nil {
		t.Fatalf("GetModel(orgB) after rejected update failed: %v", err)
	}
	if movedToB != nil {
		t.Fatalf("model was relocated into org %q despite the update being rejected", orgB)
	}

	sameOrgUpdate := &object.Model{
		Owner:       orgA,
		Name:        modelName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: modelName + "-edited",
		ModelText:   ownerGuardModelText,
	}
	resp = callUpdateWithBody(t, "update-model", tenantAdmin.GetId(), modelId, sameOrgUpdate)
	if resp.Status != "ok" {
		t.Fatalf("legitimate same-org update by the tenant admin was rejected: %+v", resp)
	}
}

// TestUpdateAdapterRejectsCrossOrgOwnerRewrite mirrors the permission case
// for adapters.
func TestUpdateAdapterRejectsCrossOrgOwnerRewrite(t *testing.T) {
	initOwnerGuardTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := "tc9b51735b-adapter-a-" + suffix
	orgB := "tc9b51735b-adapter-b-" + suffix
	adapterName := "adapter-" + suffix

	setupOwnerGuardOrg(t, orgA)
	setupOwnerGuardOrg(t, orgB)
	tenantAdmin := setupOwnerGuardUser(t, orgA, "admin", true)

	a := &object.Adapter{
		Owner:       orgA,
		Name:        adapterName,
		CreatedTime: util.GetCurrentTime(),
		Type:        "database",
		Table:       "tc9b51735b_table_" + suffix,
	}
	ok, err := object.AddAdapter(a)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture adapter: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteAdapter(&object.Adapter{Owner: orgA, Name: adapterName})
		_, _ = object.DeleteAdapter(&object.Adapter{Owner: orgB, Name: adapterName})
	})

	adapterId := a.GetId()

	moved := &object.Adapter{
		Owner:       orgB,
		Name:        adapterName,
		CreatedTime: util.GetCurrentTime(),
		Type:        "database",
		Table:       "tc9b51735b_table_" + suffix,
	}
	resp := callUpdateWithBody(t, "update-adapter", tenantAdmin.GetId(), adapterId, moved)
	if resp.Status == "ok" {
		t.Fatalf("invariant violated: org-A tenant admin moved adapter %s to org %q via update-adapter (resp=%+v)", adapterId, orgB, resp)
	}

	stillInA, err := object.GetAdapter(orgA + "/" + adapterName)
	if err != nil {
		t.Fatalf("GetAdapter(orgA) after rejected update failed: %v", err)
	}
	if stillInA == nil {
		t.Fatalf("adapter %s disappeared from org %q after a rejected owner rewrite", adapterId, orgA)
	}

	movedToB, err := object.GetAdapter(orgB + "/" + adapterName)
	if err != nil {
		t.Fatalf("GetAdapter(orgB) after rejected update failed: %v", err)
	}
	if movedToB != nil {
		t.Fatalf("adapter was relocated into org %q despite the update being rejected", orgB)
	}

	sameOrgUpdate := &object.Adapter{
		Owner:       orgA,
		Name:        adapterName,
		CreatedTime: util.GetCurrentTime(),
		Type:        "database",
		Table:       "tc9b51735b_table_edited_" + suffix,
	}
	resp = callUpdateWithBody(t, "update-adapter", tenantAdmin.GetId(), adapterId, sameOrgUpdate)
	if resp.Status != "ok" {
		t.Fatalf("legitimate same-org update by the tenant admin was rejected: %+v", resp)
	}
}

// TestUpdateEnforcerRejectsCrossOrgOwnerRewrite mirrors the permission case
// for enforcers.
func TestUpdateEnforcerRejectsCrossOrgOwnerRewrite(t *testing.T) {
	initOwnerGuardTest(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := "tc9b51735b-enforcer-a-" + suffix
	orgB := "tc9b51735b-enforcer-b-" + suffix
	enforcerName := "enforcer-" + suffix

	setupOwnerGuardOrg(t, orgA)
	setupOwnerGuardOrg(t, orgB)
	tenantAdmin := setupOwnerGuardUser(t, orgA, "admin", true)

	e := &object.Enforcer{
		Owner:       orgA,
		Name:        enforcerName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: enforcerName,
		Model:       "built-in/api-model-built-in",
		Adapter:     "built-in/api-adapter-built-in",
	}
	ok, err := object.AddEnforcer(e)
	if err != nil || !ok {
		t.Fatalf("failed to create fixture enforcer: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteEnforcer(&object.Enforcer{Owner: orgA, Name: enforcerName})
		_, _ = object.DeleteEnforcer(&object.Enforcer{Owner: orgB, Name: enforcerName})
	})

	enforcerId := e.GetId()

	moved := &object.Enforcer{
		Owner:       orgB,
		Name:        enforcerName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: enforcerName,
		Model:       "built-in/api-model-built-in",
		Adapter:     "built-in/api-adapter-built-in",
	}
	resp := callUpdateWithBody(t, "update-enforcer", tenantAdmin.GetId(), enforcerId, moved)
	if resp.Status == "ok" {
		t.Fatalf("invariant violated: org-A tenant admin moved enforcer %s to org %q via update-enforcer (resp=%+v)", enforcerId, orgB, resp)
	}

	stillInA, err := object.GetEnforcer(orgA + "/" + enforcerName)
	if err != nil {
		t.Fatalf("GetEnforcer(orgA) after rejected update failed: %v", err)
	}
	if stillInA == nil {
		t.Fatalf("enforcer %s disappeared from org %q after a rejected owner rewrite", enforcerId, orgA)
	}

	movedToB, err := object.GetEnforcer(orgB + "/" + enforcerName)
	if err != nil {
		t.Fatalf("GetEnforcer(orgB) after rejected update failed: %v", err)
	}
	if movedToB != nil {
		t.Fatalf("enforcer was relocated into org %q despite the update being rejected", orgB)
	}

	sameOrgUpdate := &object.Enforcer{
		Owner:       orgA,
		Name:        enforcerName,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: enforcerName + "-edited",
		Model:       "built-in/api-model-built-in",
		Adapter:     "built-in/api-adapter-built-in",
	}
	resp = callUpdateWithBody(t, "update-enforcer", tenantAdmin.GetId(), enforcerId, sameOrgUpdate)
	if resp.Status != "ok" {
		t.Fatalf("legitimate same-org update by the tenant admin was rejected: %+v", resp)
	}
}
