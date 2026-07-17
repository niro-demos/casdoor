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
	"testing"

	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/casdoor/casdoor/object"
	stringadapter "github.com/qiangmzsx/string-adapter/v2"
)

// newTestEnforcer builds a fresh, in-memory Casbin enforcer from the exact
// production model (object.BuiltInApiModelText) and policy
// (apiPolicyRuleText) used by built-in/api-model-built-in, with no DB and no
// running server involved. This lets the invariant under test -- whether the
// self-match clause of the matcher grants access -- be exercised directly
// against the real matcher text that ships in object/init.go.
func newTestEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()

	md := casbinmodel.NewModel()
	if err := md.LoadModelFromText(object.BuiltInApiModelText); err != nil {
		t.Fatalf("failed to load built-in api model: %v", err)
	}

	sa := stringadapter.NewAdapter(apiPolicyRuleText)
	e, err := casbin.NewEnforcer(md, sa)
	if err != nil {
		t.Fatalf("failed to build enforcer: %v", err)
	}
	return e
}

// TestSelfNameMatcherDoesNotBypassAdminPlaneEntities is the regression test
// for TC-67D66F95: a standard, non-admin user ("acme/alice") must not be able
// to create or modify Role, Permission, Adapter, or Enforcer objects just
// because the object's owner/name happens to equal her own owner/name. The
// invariant is isolated with a positive control (an arbitrarily-named object
// is correctly denied) and a legitimate self-service control (updating her
// own User record, and only her own, must keep working) so a failure here is
// attributable to the self-name bypass and not a broken matcher/policy.
func TestSelfNameMatcherDoesNotBypassAdminPlaneEntities(t *testing.T) {
	e := newTestEnforcer(t)

	const subOwner = "acme"
	const subName = "alice"

	adminPlaneCases := []struct {
		name   string
		method string
		path   string
	}{
		{"add-role", "POST", "/api/add-role"},
		{"update-role", "POST", "/api/update-role"},
		{"add-permission", "POST", "/api/add-permission"},
		{"update-permission", "POST", "/api/update-permission"},
		{"add-adapter", "POST", "/api/add-adapter"},
		{"add-enforcer", "POST", "/api/add-enforcer"},
	}

	for _, tc := range adminPlaneCases {
		t.Run(tc.name+"/self-name-object-must-be-denied", func(t *testing.T) {
			// The exploit: the object's owner/name is set to the caller's own
			// owner/name (acme/alice), even though the object is a
			// Role/Permission/Adapter/Enforcer, not alice's User record.
			ok, err := e.Enforce(subOwner, subName, tc.method, tc.path, subOwner, subName)
			if err != nil {
				t.Fatalf("Enforce error: %v", err)
			}
			if ok {
				t.Fatalf("INVARIANT VIOLATED: non-admin %s/%s was allowed to %s %s on object %s/%s "+
					"(self-name matcher bypass) -- a standard user must never be able to write "+
					"Role/Permission/Adapter/Enforcer objects by name-matching alone",
					subOwner, subName, tc.method, tc.path, subOwner, subName)
			}
		})

		t.Run(tc.name+"/arbitrary-name-object-control-must-stay-denied", func(t *testing.T) {
			// Positive control: an arbitrarily-named object (not matching the
			// caller) must remain denied, proving the deny path itself is
			// healthy for this endpoint both before and after the fix.
			ok, err := e.Enforce(subOwner, subName, tc.method, tc.path, subOwner, "some-other-object-name")
			if err != nil {
				t.Fatalf("Enforce error: %v", err)
			}
			if ok {
				t.Fatalf("HARNESS ERROR: non-admin %s/%s was allowed to %s %s on an arbitrarily-named "+
					"object -- the deny path is broken independent of the self-name bypass, "+
					"so this test cannot isolate the invariant", subOwner, subName, tc.method, tc.path)
			}
		})
	}
}

// TestSelfNameMatcherStillAllowsGenuineUserSelfService guards against the fix
// for TC-67D66F95 overcorrecting: a user must still be able to manage her own
// User account (update-user, delete-user) via the self-match clause, since
// those endpoints have no explicit policy row and rely on it entirely, and
// she must NOT be able to do so for another user's account.
func TestSelfNameMatcherStillAllowsGenuineUserSelfService(t *testing.T) {
	e := newTestEnforcer(t)

	const subOwner = "acme"
	const subName = "alice"

	selfServiceCases := []struct {
		name   string
		method string
		path   string
	}{
		{"update-user", "POST", "/api/update-user"},
		{"delete-user", "POST", "/api/delete-user"},
	}

	for _, tc := range selfServiceCases {
		t.Run(tc.name+"/own-account-must-be-allowed", func(t *testing.T) {
			ok, err := e.Enforce(subOwner, subName, tc.method, tc.path, subOwner, subName)
			if err != nil {
				t.Fatalf("Enforce error: %v", err)
			}
			if !ok {
				t.Fatalf("REGRESSION: non-admin %s/%s was denied %s %s on her own account "+
					"(%s/%s) -- legitimate user self-service must keep working",
					subOwner, subName, tc.method, tc.path, subOwner, subName)
			}
		})

		t.Run(tc.name+"/other-users-account-must-stay-denied", func(t *testing.T) {
			ok, err := e.Enforce(subOwner, subName, tc.method, tc.path, subOwner, "bob")
			if err != nil {
				t.Fatalf("Enforce error: %v", err)
			}
			if ok {
				t.Fatalf("INVARIANT VIOLATED: non-admin %s/%s was allowed to %s %s on another "+
					"user's account (%s/bob)", subOwner, subName, tc.method, tc.path, subOwner)
			}
		})
	}
}
