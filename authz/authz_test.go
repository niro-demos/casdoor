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
)

var authzTestEnvOnce sync.Once

// setupAuthzTestEnv bootstraps a real (local) database connection and loads
// the built-in casbin policy, mirroring what main.go does at startup:
// object.InitConfig() -> object.InitDb() -> authz.InitApi(). It is safe to
// call from every test in this file; the underlying init is idempotent and
// only runs once per test binary.
func setupAuthzTestEnv(t *testing.T) {
	t.Helper()
	authzTestEnvOnce.Do(func() {
		object.InitConfig()
		object.InitDb()
		InitApi()
	})
}

// TestIsAllowedAppCredentialCannotAccessForeignOrganization is the
// regression test for the CRITICAL finding: a valid OAuth application
// client_id/client_secret pair (subOwner == "app") must be scoped to its own
// organization, not grant instance-wide access to every other
// organization's data.
//
// Before the fix, IsAllowed() unconditionally returned true for any
// subOwner == "app" request regardless of which organization's resource
// (objOwner) was being targeted - this test's "cross-org" cases reproduce
// that bypass (mirroring the add-webhook / get-users exploit steps from the
// PoC) and must fail (deny) once fixed. The "same-org" case is a positive
// control proving the app principal is not simply locked out everywhere -
// only outside its own organization.
func TestIsAllowedAppCredentialCannotAccessForeignOrganization(t *testing.T) {
	setupAuthzTestEnv(t)

	const appOrg = "authz-test-org-owner"
	const foreignOrg = "authz-test-org-foreign"
	extraInfo := map[string]interface{}{"appOrganization": appOrg}

	cases := []struct {
		name        string
		method      string
		urlPath     string
		objOwner    string
		objName     string
		wantAllowed bool
	}{
		{
			name:        "cross-org webhook write is denied",
			method:      "POST",
			urlPath:     "/api/add-webhook",
			objOwner:    foreignOrg,
			objName:     "attacker-webhook",
			wantAllowed: false,
		},
		{
			name:        "cross-org user read is denied",
			method:      "GET",
			urlPath:     "/api/get-users",
			objOwner:    foreignOrg,
			objName:     "",
			wantAllowed: false,
		},
		{
			// Positive control: the same app principal must still be able to
			// act within its own organization - proves the deny above is the
			// org-scoping invariant, not the app credential being rejected
			// outright.
			name:        "same-org webhook read is allowed (control)",
			method:      "GET",
			urlPath:     "/api/get-webhooks",
			objOwner:    appOrg,
			objName:     "",
			wantAllowed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := IsAllowed("app", "authz-test-app", tc.method, tc.urlPath, tc.objOwner, tc.objName, extraInfo)
			if err != nil {
				t.Fatalf("IsAllowed() returned an error: %v", err)
			}
			if allowed != tc.wantAllowed {
				t.Fatalf("IsAllowed(subOwner=%q, appOrganization=%q, objOwner=%q) = %v, want %v",
					"app", appOrg, tc.objOwner, allowed, tc.wantAllowed)
			}
		})
	}
}

// TestIsAllowedAppCredentialStillReachesIntentionallyPublicEndpoints guards
// against over-correcting the org-scoping fix: an app principal must not
// become *more* restricted than an anonymous caller on an endpoint that is
// intentionally open to everyone (a "p, *, *, ..." policy line), just
// because the request targets a different organization or none at all. The
// org-scoping check only removes the old blanket bypass for
// resources *outside* the app's own organization - it must fall through to
// the normal policy engine, not auto-deny, so endpoints like
// /api/get-organizations (open to any subject) keep working for an app
// principal exactly as they do today.
func TestIsAllowedAppCredentialStillReachesIntentionallyPublicEndpoints(t *testing.T) {
	setupAuthzTestEnv(t)

	extraInfo := map[string]interface{}{"appOrganization": "authz-test-org-owner"}

	allowed, err := IsAllowed("app", "authz-test-app", "GET", "/api/get-organizations", "authz-test-org-foreign", "", extraInfo)
	if err != nil {
		t.Fatalf("IsAllowed() returned an error: %v", err)
	}
	if !allowed {
		t.Fatalf("IsAllowed() = false for a wildcard-open policy endpoint (/api/get-organizations) targeting a foreign org, want true - an app principal must not be more restricted than an anonymous caller on an intentionally public endpoint")
	}
}

// TestIsAllowedAppCredentialWithoutOrganizationInfoIsDenied guards the
// fail-safe default: if extraInfo somehow does not carry the authenticated
// application's organization (e.g. a future caller of IsAllowed forgets to
// populate it), an owner-scoped request must be denied rather than silently
// falling back to the old "allow everything" behavior.
func TestIsAllowedAppCredentialWithoutOrganizationInfoIsDenied(t *testing.T) {
	setupAuthzTestEnv(t)

	allowed, err := IsAllowed("app", "authz-test-app", "GET", "/api/get-users", "authz-test-org-foreign", "", nil)
	if err != nil {
		t.Fatalf("IsAllowed() returned an error: %v", err)
	}
	if allowed {
		t.Fatalf("IsAllowed() = true for an owner-scoped request with no appOrganization in extraInfo, want false (fail-safe deny)")
	}
}
