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

package routers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var routersTestEnvOnce sync.Once

func setupRoutersTestEnv(t *testing.T) {
	t.Helper()
	routersTestEnvOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
	})
}

func newTestContext(rawQuery string) *context.Context {
	req := httptest.NewRequest(http.MethodGet, "/api/add-webhook?"+rawQuery, nil)
	w := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(w, req)
	return ctx
}

// TestGetUsernameByClientIdSecretStashesAppOrganization is the wiring
// regression test for the org-scoping fix in authz.IsAllowed(): it proves
// that once an application authenticates via ?clientId=&clientSecret=,
// getUsernameByClientIdSecret() stashes that application's own organization
// on the request context, and getExtraInfo() forwards it - the exact
// plumbing authz.IsAllowed() relies on to scope an "app" principal to its
// own organization instead of granting it instance-wide access.
func TestGetUsernameByClientIdSecretStashesAppOrganization(t *testing.T) {
	setupRoutersTestEnv(t)

	org := "routers-test-org-" + util.GenerateId()
	application := &object.Application{
		Owner:        "admin",
		Name:         "routers-test-app-" + util.GenerateId(),
		Organization: org,
		ClientId:     "routers-test-client-" + util.GenerateId(),
		ClientSecret: "routers-test-secret-" + util.GenerateId(),
	}
	ok, err := object.AddApplication(application)
	if err != nil {
		t.Fatalf("AddApplication() error = %v", err)
	}
	if !ok {
		t.Fatalf("AddApplication() = false, want true")
	}
	defer func() {
		_, _ = object.DeleteApplication(application)
	}()

	ctx := newTestContext(fmt.Sprintf("clientId=%s&clientSecret=%s", application.ClientId, application.ClientSecret))

	username, err := getUsernameByClientIdSecret(ctx)
	if err != nil {
		t.Fatalf("getUsernameByClientIdSecret() error = %v", err)
	}

	wantUsername := "app/" + application.Name
	if username != wantUsername {
		t.Fatalf("getUsernameByClientIdSecret() = %q, want %q", username, wantUsername)
	}

	gotOrg, ok := ctx.Input.GetData("appOrganization").(string)
	if !ok || gotOrg != org {
		t.Fatalf(`ctx.Input.GetData("appOrganization") = %q (ok=%v), want %q`, gotOrg, ok, org)
	}

	// getExtraInfo must forward the same value so authz.IsAllowed() can see it.
	extra := getExtraInfo(ctx, "/api/add-webhook")
	if extra == nil {
		t.Fatalf("getExtraInfo() = nil, want a map containing appOrganization")
	}
	if got, _ := extra["appOrganization"].(string); got != org {
		t.Fatalf(`getExtraInfo()["appOrganization"] = %q, want %q`, got, org)
	}
}

// TestGetUsernameByClientIdSecretNoAppOrganizationWithoutCredentials proves
// the new SetData call does not fire (and getExtraInfo does not fabricate an
// appOrganization) for a request that never authenticated as an application -
// i.e. a normal, credential-less GET request.
func TestGetUsernameByClientIdSecretNoAppOrganizationWithoutCredentials(t *testing.T) {
	setupRoutersTestEnv(t)

	ctx := newTestContext("")

	username, err := getUsernameByClientIdSecret(ctx)
	if err != nil {
		t.Fatalf("getUsernameByClientIdSecret() error = %v", err)
	}
	if username != "" {
		t.Fatalf("getUsernameByClientIdSecret() = %q, want empty (no credentials supplied)", username)
	}

	if _, ok := ctx.Input.GetData("appOrganization").(string); ok {
		t.Fatalf("ctx.Input.GetData(\"appOrganization\") set without any app credentials being presented")
	}

	extra := getExtraInfo(ctx, "/api/add-webhook")
	if extra != nil {
		t.Fatalf("getExtraInfo() = %#v, want nil for a plain request with no app credentials and no mcp path", extra)
	}
}
