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

package object

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	stringadapter "github.com/qiangmzsx/string-adapter/v2"
)

// TestIsSelfServiceApiPath pins the scoping table for the self-service matcher
// fallback: admin-managed object-type paths are excluded (return false), while
// genuine self-service endpoints that act on the caller's own account object
// remain eligible (return true). Regressing either direction would either
// re-open the escalation or break legitimate self-service.
func TestIsSelfServiceApiPath(t *testing.T) {
	// Admin-managed object types the self-service clause must never authorize.
	excluded := []string{
		"/api/add-role", "/api/update-role", "/api/delete-role",
		"/api/add-permission", "/api/update-permission", "/api/delete-permission",
		"/api/add-server", "/api/update-server", "/api/delete-server", "/api/sync-mcp-tool",
		"/api/add-model", "/api/add-adapter", "/api/add-enforcer",
		"/api/add-policy", "/api/update-policy", "/api/remove-policy",
	}
	for _, p := range excluded {
		if IsSelfServiceApiPath(p) {
			t.Errorf("IsSelfServiceApiPath(%q) = true, want false (admin-managed object type)", p)
		}
	}

	// Genuine self-service endpoints acting on the caller's own account object;
	// these must stay eligible for the fallback.
	selfService := []string{
		"/api/update-user", "/api/set-password", "/api/delete-mfa",
		"/api/upload-resource", "/api/delete-resource",
	}
	for _, p := range selfService {
		if !IsSelfServiceApiPath(p) {
			t.Errorf("IsSelfServiceApiPath(%q) = false, want true (legitimate self-service)", p)
		}
	}
}

// newBuiltInApiEnforcer builds an in-memory Casbin enforcer from the built-in
// API model (the single source of truth used to seed the DB in
// initBuiltInApiModel) plus a policy set. It registers the same custom matcher
// functions the production enforcer uses, so the self-service fallback clause
// behaves exactly as it does at runtime. No database is involved.
func newBuiltInApiEnforcer(t *testing.T, policy string) *casbin.Enforcer {
	t.Helper()

	m, err := model.NewModelFromString(BuiltInApiModelText)
	if err != nil {
		t.Fatalf("failed to parse BuiltInApiModelText: %v", err)
	}

	e, err := casbin.NewEnforcer(m, stringadapter.NewAdapter(policy))
	if err != nil {
		t.Fatalf("failed to build enforcer: %v", err)
	}
	registerBuiltInApiFunctions(e)
	return e
}

// TestSelfServiceFallbackDoesNotAuthorizeAdminManagedObjects asserts the
// security invariant behind TC-F996DFE3 and TC-1E768CA4:
//
// A regular, non-admin user must NOT be able to self-authorize a mutation on an
// admin-managed object type (role, permission, server, and the sibling
// authorization/admin-infra object types) merely by naming the new object after
// her own username so that (objOwner, objName) == (subOwner, subName).
//
// The self-service matcher fallback exists only for a user acting on her own
// account object (e.g. POST /api/update-user where objName == her username), so
// that legitimate case is asserted as a green control: it proves the clause is
// still wired up and the test environment is healthy, isolating any red result
// to the admin-managed object types rather than a broken setup.
func TestSelfServiceFallbackDoesNotAuthorizeAdminManagedObjects(t *testing.T) {
	// The policy grants the non-admin subject NOTHING for the endpoints under
	// test. The single line below only authorizes an unrelated global-admin-style
	// subject on unrelated paths; it exists solely so the string adapter parses a
	// non-empty policy. There is deliberately no `p, ..., /api/add-role, ...` line
	// (and none for add-permission / add-server / etc.), so the ONLY thing that
	// could authorize the requests under test is the self-service fallback clause
	// in the matcher. This mirrors production, where no Casbin policy line covers
	// these admin-only mutation endpoints for a plain member.
	const policy = `p, built-in, admin, *, /api/unrelated-endpoint, *, *`

	e := newBuiltInApiEnforcer(t, policy)

	// A non-admin user acme/bob. In every exploit case objOwner/objName are the
	// attacker-controlled body values, set equal to the subject to trip the
	// self-service clause.
	const subOwner, subName = "acme", "bob"

	// Green control: legitimate self-service on the caller's OWN account object.
	// This MUST be allowed both before and after the fix — it is the behavior the
	// self-service clause exists to preserve.
	allowed, err := e.Enforce(subOwner, subName, "POST", "/api/update-user", subOwner, subName)
	if err != nil {
		t.Fatalf("control Enforce error: %v", err)
	}
	if !allowed {
		t.Fatalf("control FAILED: legitimate self-service POST /api/update-user on own account was denied; "+
			"the self-service clause or test setup is broken (sub=%s/%s)", subOwner, subName)
	}

	// Exploit cases: admin-managed object types the reported findings abused
	// (role, permission, server) plus their sibling authorization/admin-infra
	// object types that share the identical self-name bypass shape. For each,
	// the non-admin names the object after herself. Every one MUST be denied.
	exploitPaths := []string{
		// TC-F996DFE3 — self-create Role / self-approve Permission.
		"/api/add-role",
		"/api/update-role",
		"/api/delete-role",
		"/api/add-permission",
		"/api/update-permission",
		"/api/delete-permission",
		// TC-1E768CA4 — create/modify MCP Server entries (→ SSRF via proxy).
		"/api/add-server",
		"/api/update-server",
		"/api/delete-server",
		"/api/sync-mcp-tool",
		// Sibling admin-managed object types with the same (owner,name) PK and
		// body-derived object identity.
		"/api/add-model",
		"/api/add-adapter",
		"/api/add-enforcer",
	}

	for _, path := range exploitPaths {
		allowed, err := e.Enforce(subOwner, subName, "POST", path, subOwner, subName)
		if err != nil {
			t.Fatalf("Enforce error for %s: %v", path, err)
		}
		if allowed {
			t.Errorf("INVARIANT VIOLATED: non-admin %s/%s self-authorized admin-managed mutation %s "+
				"by naming the object after herself (objOwner=%s, objName=%s). "+
				"The self-service matcher clause must not apply to admin-managed object types.",
				subOwner, subName, path, subOwner, subName)
		}
	}
}
