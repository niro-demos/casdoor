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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// newTestContext builds a minimal beego context around a JSON POST body, the
// same shape ApiFilter sees once RequestBodyFilter has cached the raw body.
func newTestContext(t *testing.T, method, path, body string) *context.Context {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ctx := context.NewContext()
	ctx.Reset(rec, req)
	ctx.Input.RequestBody = []byte(body)

	return ctx
}

// TestGetObjectSelfBypassCannotBeGamedByUserField is the shared-root-cause
// regression test for TC-D88C1B09, TC-B919E08F and TC-DEFC6A99.
//
// The Casbin self-service bypass in object/init.go's built-in API model
// grants access whenever r.subOwner==r.objOwner && r.subName==r.objName.
// getObject() used to derive objName purely from the request body's
// owner/name fields. For /api/add-subscription, /api/update-subscription,
// /api/add-transaction, /api/update-transaction, /api/add-token and
// /api/update-token, the body's owner/name identify the caller's own record,
// but a separate "user" field designates the account the write actually
// targets. A caller could keep owner/name equal to their own identity (so
// the self-bypass matched) while setting "user" to a different, more
// privileged victim, escalating on that victim's behalf.
//
// The invariant: for these endpoints, objName must reflect the body's
// "user" field (the true target of the write) whenever present, so the
// self-bypass condition (subName == objName) only holds when the caller is
// actually acting on their own account.
func TestGetObjectSelfBypassCannotBeGamedByUserField(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		wantOwner  string
		wantObject string
	}{
		{
			name: "add-subscription gift to a different named user is not the caller's own object",
			path: "/api/add-subscription",
			body: `{"owner":"acme","name":"alice","user":"bob","state":"Active"}`,
			// Before the fix this returned "alice" (attacker-controlled),
			// which would equal the caller's own subName and wrongly satisfy
			// the self-bypass. It must resolve to the real target, "bob".
			wantOwner:  "acme",
			wantObject: "bob",
		},
		{
			name:       "add-subscription self-grant still resolves to the caller",
			path:       "/api/add-subscription",
			body:       `{"owner":"acme","name":"alice","user":"alice","state":"Active"}`,
			wantOwner:  "acme",
			wantObject: "alice",
		},
		{
			name:       "add-transaction credit to a different named user is not the caller's own object",
			path:       "/api/add-transaction",
			body:       `{"owner":"acme","name":"alice","user":"bob","amount":50000}`,
			wantOwner:  "acme",
			wantObject: "bob",
		},
		{
			name:       "add-transaction self-credit still resolves to the caller",
			path:       "/api/add-transaction",
			body:       `{"owner":"acme","name":"alice","user":"alice","amount":50000}`,
			wantOwner:  "acme",
			wantObject: "alice",
		},
		{
			name: "update-token forged to impersonate a different user is not the caller's own object",
			path: "/api/update-token",
			body: `{"owner":"acme","name":"alice","organization":"acme","user":"acme-admin","accessToken":"forged"}`,
			// Before the fix this returned "alice" (the token row's own
			// name field, attacker-controlled), wrongly satisfying the
			// self-bypass even though "user" names the victim.
			wantOwner:  "acme",
			wantObject: "acme-admin",
		},
		{
			name:       "update-token for the caller's own account still resolves to the caller",
			path:       "/api/update-token",
			body:       `{"owner":"acme","name":"alice","organization":"acme","user":"alice","accessToken":"legit"}`,
			wantOwner:  "acme",
			wantObject: "alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestContext(t, "POST", tt.path, tt.body)
			gotOwner, gotObject, err := getObject(ctx)
			if err != nil {
				t.Fatalf("getObject() returned error: %v", err)
			}
			if gotOwner != tt.wantOwner || gotObject != tt.wantObject {
				t.Fatalf("getObject() = (%q, %q), want (%q, %q)", gotOwner, gotObject, tt.wantOwner, tt.wantObject)
			}
		})
	}
}
