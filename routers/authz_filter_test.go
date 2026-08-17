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

package routers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// newTestContext builds a beego *context.Context wrapping a bare HTTP
// request/response pair, sufficient for exercising getObject() in isolation
// (no session, no DB) the same way ApiFilter does at request time.
func newTestContext(method, target string) *context.Context {
	r := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(w, r)
	return ctx
}

// TestGetObjectGetPoliciesUsesAdapterIdWheneverPresent covers TC-2AC9D8A3.
//
// controllers/enforcer.go GetPolicies() gives `adapterId` unconditional
// priority over `id` whenever adapterId is non-empty. The authz object
// returned by getObject() must therefore be derived from `adapterId`
// whenever it is present, regardless of what `id` is set to - otherwise the
// tenant-ownership check (subOwner == objOwner) validates a different
// resource than the one the controller actually acts on, letting a caller
// pair an in-tenant `id` with an out-of-tenant `adapterId` to reach another
// org's adapter.
func TestGetObjectGetPoliciesUsesAdapterIdWheneverPresent(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		wantOwner string
		wantName  string
	}{
		{
			name:      "mismatched id/adapterId (attack shape) resolves from adapterId, matching the controller",
			url:       "/api/get-policies?id=niro-alpha/fake-enforcer&adapterId=niro-beta/secret-adapter",
			wantOwner: "niro-beta",
			wantName:  "secret-adapter",
		},
		{
			name:      "id=/ with adapterId resolves from adapterId (pre-existing behavior, must not regress)",
			url:       "/api/get-policies?id=%2F&adapterId=niro-beta/secret-adapter",
			wantOwner: "niro-beta",
			wantName:  "secret-adapter",
		},
		{
			name:      "no adapterId falls back to id",
			url:       "/api/get-policies?id=niro-alpha/enforcer1",
			wantOwner: "niro-alpha",
			wantName:  "enforcer1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := newTestContext(http.MethodGet, c.url)
			owner, name, err := getObject(ctx)
			if err != nil {
				t.Fatalf("getObject() returned unexpected error: %v", err)
			}
			if owner != c.wantOwner || name != c.wantName {
				t.Fatalf("getObject() = (%q, %q), want (%q, %q); the authz object must always match what controllers/enforcer.go GetPolicies() acts on",
					owner, name, c.wantOwner, c.wantName)
			}
		})
	}
}

// TestGetObjectIgnoresOrganizationOverrideForIdBasedLookups covers TC-AF996616.
//
// For GET-by-id lookups, getObject() must derive the authz object owner from
// the real owner encoded in `id`, never from the client-supplied
// `organization` query parameter - controllers/cert.go GetCert() and
// controllers/model.go GetModel() fetch strictly by `id` and never
// re-validate the caller's organization, so if getObject() let `organization`
// override the real owner, a same-org-admin check would pass for a
// different tenant's resource.
func TestGetObjectIgnoresOrganizationOverrideForIdBasedLookups(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		wantOwner string
		wantName  string
	}{
		{
			name:      "get-cert: organization override must not replace the real owner parsed from id",
			url:       "/api/get-cert?id=niro-alpha/vector-cert-1&organization=niro-beta",
			wantOwner: "niro-alpha",
			wantName:  "vector-cert-1",
		},
		{
			name:      "get-model: organization override must not replace the real owner parsed from id",
			url:       "/api/get-model?id=niro-alpha/vector-model-1&organization=niro-beta",
			wantOwner: "niro-alpha",
			wantName:  "vector-model-1",
		},
		{
			name:      "get-cert: no organization param - real owner from id (control)",
			url:       "/api/get-cert?id=niro-alpha/vector-cert-1",
			wantOwner: "niro-alpha",
			wantName:  "vector-cert-1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := newTestContext(http.MethodGet, c.url)
			owner, name, err := getObject(ctx)
			if err != nil {
				t.Fatalf("getObject() returned unexpected error: %v", err)
			}
			if owner != c.wantOwner || name != c.wantName {
				t.Fatalf("getObject() = (%q, %q), want (%q, %q); the authz object owner must always be the resource's real owner parsed from id",
					owner, name, c.wantOwner, c.wantName)
			}
		})
	}
}

// TestGetObjectOrganizationStillScopesListEndpoints is a guard rail: the
// `organization` query parameter legitimately selects which org's *list* to
// query on GET-many endpoints (no `id` present at all), and that usage must
// keep working after the id-based override is removed.
func TestGetObjectOrganizationStillScopesListEndpoints(t *testing.T) {
	ctx := newTestContext(http.MethodGet, "/api/get-certs?organization=niro-beta")
	owner, _, err := getObject(ctx)
	if err != nil {
		t.Fatalf("getObject() returned unexpected error: %v", err)
	}
	if owner != "niro-beta" {
		t.Fatalf("getObject() owner = %q, want %q (organization must still scope list-type endpoints)", owner, "niro-beta")
	}
}
