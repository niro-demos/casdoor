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
	"net/http"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// newGetContext builds a minimal beego context for a GET request at rawURL,
// which is all getObject() reads from for the paths under test (it consults
// ctx.Request.Method, ctx.Request.URL.Path and ctx.Input.Query(...)).
func newGetContext(t *testing.T, rawURL string) *context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("failed to build request for %q: %v", rawURL, err)
	}
	ctx := context.NewContext()
	ctx.Reset(nil, req)
	return ctx
}

// TestGetObjectHonorsIdOwnerOverOrganizationParam is the regression test for the
// cross-tenant read via `organization` param confusion.
//
// Invariant: for a GET whose `id` names a resource, the object owner used for
// the authorization decision MUST be derived from `id` (the true, persisted
// owner) and MUST NOT be overridden by the attacker-supplied `organization`
// query parameter. Otherwise an org admin passes the `subOwner == objOwner`
// scope check against their OWN org while the controller still fetches a
// different tenant's resource by `id`.
func TestGetObjectHonorsIdOwnerOverOrganizationParam(t *testing.T) {
	// Attack: id points at org-beta's entry, but organization=org-alpha (the
	// attacker's own org) is appended to trick the authz owner into org-alpha.
	ctx := newGetContext(t,
		"http://localhost:8000/api/get-entry?id=org-beta/secret-session-vector-1&organization=org-alpha")

	owner, name, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject returned unexpected error: %v", err)
	}

	// INVARIANT: the object owner must be the id-derived org-beta, never the
	// attacker-supplied org-alpha.
	if owner != "org-beta" {
		t.Fatalf("cross-tenant confusion: object owner = %q, want %q "+
			"(the `organization` query param must not override the id-derived owner)",
			owner, "org-beta")
	}
	if name != "secret-session-vector-1" {
		t.Fatalf("object name = %q, want %q", name, "secret-session-vector-1")
	}
}

// TestGetObjectIdOwnerWithoutOrganizationParam is the positive control: without
// the decoy `organization` param, getObject already returns the id-derived
// owner. Pairing it with the attack case proves the failure above is the
// invariant, not a broken parse of `id`.
func TestGetObjectIdOwnerWithoutOrganizationParam(t *testing.T) {
	ctx := newGetContext(t,
		"http://localhost:8000/api/get-entry?id=org-beta/secret-session-vector-1")

	owner, name, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject returned unexpected error: %v", err)
	}
	if owner != "org-beta" || name != "secret-session-vector-1" {
		t.Fatalf("baseline id parse wrong: got (%q, %q), want (%q, %q)",
			owner, name, "org-beta", "secret-session-vector-1")
	}
}

// TestGetObjectOrganizationParamStillUsedForListWithoutId guards the legitimate
// use of the `organization` param: on an id-absent list request there is no id
// to derive an owner from, so an org admin may still scope the listing to their
// own org via `organization`. The fix must not break this path.
func TestGetObjectOrganizationParamStillUsedForListWithoutId(t *testing.T) {
	ctx := newGetContext(t,
		"http://localhost:8000/api/get-entries?organization=org-alpha")

	owner, _, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject returned unexpected error: %v", err)
	}
	if owner != "org-alpha" {
		t.Fatalf("list-scope owner = %q, want %q (organization param must still "+
			"scope id-absent list requests)", owner, "org-alpha")
	}
}
