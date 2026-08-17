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

package authz

import (
	"sync"
	"testing"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var initTestDbOnce sync.Once

// initTestDb wires up the same DB the running app uses (conf/app.conf),
// mirroring object.TestDumpToFile's setup convention, and seeds the built-in
// rows IsAllowed depends on (organizations/applications/enforcer policy).
func initTestDb(t *testing.T) {
	t.Helper()
	initTestDbOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
		InitApi()
	})
}

// TestIsAllowedScopesAppClientCredentialsToOwnOrganization reproduces
// TC-A2059D90: an application's own OAuth clientId/clientSecret must not act
// as a platform-wide skeleton key. A caller authenticated only as
// subOwner=="app" (see routers.getUsernameByClientIdSecret) must be confined
// to its own application's organization, not granted unconditional access to
// every other tenant's data.
func TestIsAllowedScopesAppClientCredentialsToOwnOrganization(t *testing.T) {
	initTestDb(t)

	suffix := util.GenerateId()[:8]
	orgAlphaName := "authz-test-org-alpha-" + suffix
	orgBetaName := "authz-test-org-beta-" + suffix
	appName := "authz-test-app-alpha-" + suffix

	orgAlpha := &object.Organization{Owner: "admin", Name: orgAlphaName, DisplayName: "Alpha"}
	orgBeta := &object.Organization{Owner: "admin", Name: orgBetaName, DisplayName: "Beta"}
	if ok, err := object.AddOrganization(orgAlpha); err != nil || !ok {
		t.Fatalf("failed to seed org alpha: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(orgAlpha) })
	if ok, err := object.AddOrganization(orgBeta); err != nil || !ok {
		t.Fatalf("failed to seed org beta: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(orgBeta) })

	app := &object.Application{Owner: "admin", Name: appName, Organization: orgAlphaName, DisplayName: "Alpha App"}
	if ok, err := object.AddApplication(app); err != nil || !ok {
		t.Fatalf("failed to seed application: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(app) })

	// POSITIVE CONTROL: a real niro-alpha admin (session-authenticated,
	// subOwner==orgAlphaName) must never be able to read org beta's data --
	// this establishes the baseline the app-credential path must match, not
	// exceed.
	controlAllowed, err := IsAllowed(orgAlphaName, "admin", "GET", "/api/get-tickets", orgBetaName, "", nil)
	if err != nil {
		t.Fatalf("control IsAllowed error: %v", err)
	}
	if controlAllowed {
		t.Fatalf("environment is broken: a session-authenticated org-alpha admin was allowed to read org-beta's tickets directly")
	}

	// THE VIOLATION: subOwner=="app" is exactly what
	// routers.getUsernameByClientIdSecret returns for any request
	// authenticated via a valid clientId/clientSecret pair -- with no
	// session at all. It must be denied identically to the control above.
	violationAllowed, err := IsAllowed("app", appName, "GET", "/api/get-tickets", orgBetaName, "", nil)
	if err != nil {
		t.Fatalf("IsAllowed error: %v", err)
	}
	if violationAllowed {
		t.Fatalf("invariant violated: app %q's own client credentials (scoped to organization %q) were allowed to read organization %q's tickets", appName, orgAlphaName, orgBetaName)
	}

	// GREEN CONTROL: the same app credentials must still work for the
	// application's own organization -- the fix must not break legitimate
	// same-tenant SDK usage.
	sameOrgAllowed, err := IsAllowed("app", appName, "GET", "/api/get-tickets", orgAlphaName, "", nil)
	if err != nil {
		t.Fatalf("IsAllowed error (same org): %v", err)
	}
	if !sameOrgAllowed {
		t.Fatalf("regression: app %q's own client credentials were denied access to its own organization %q", appName, orgAlphaName)
	}
}
