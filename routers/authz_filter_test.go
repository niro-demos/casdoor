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
	"testing"

	beegocontext "github.com/beego/beego/v2/server/web/context"
)

func TestGetObjectBindsSessionAuthorizationToSessionPkId(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantOwner string
		wantName  string
	}{
		{
			name:      "legitimate own session lookup",
			query:     "sessionPkId=niro-alpha%2Falice%2Fapp-niro-alpha&id=niro-alpha%2Falice",
			wantOwner: "niro-alpha",
			wantName:  "alice",
		},
		{
			name:      "unrelated id cannot replace selected session owner",
			query:     "sessionPkId=built-in%2Fadmin%2Fapp-built-in&id=niro-alpha%2Falice",
			wantOwner: "built-in",
			wantName:  "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/get-session?"+tt.query, nil)
			ctx := beegocontext.NewContext()
			ctx.Reset(httptest.NewRecorder(), req)

			owner, name, err := getObject(ctx)
			if err != nil {
				t.Fatalf("getObject() error = %v", err)
			}
			if owner != tt.wantOwner || name != tt.wantName {
				t.Fatalf("getObject() = %q/%q, want %q/%q", owner, name, tt.wantOwner, tt.wantName)
			}
		})
	}
}
