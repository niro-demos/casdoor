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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
)

func TestUpdatePolicyRejectsEmptyPolicyArray(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/update-policy?id=built-in%2Fuser-enforcer-built-in", strings.NewReader("[]"))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.RequestBody = []byte("[]")

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "UpdatePolicy", nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UpdatePolicy() panicked for empty policy array instead of returning a controlled error: %v", r)
		}
	}()

	controller.UpdatePolicy()

	resp, ok := controller.Data["json"].(*Response)
	if !ok {
		t.Fatalf("UpdatePolicy() response type = %T, want *Response", controller.Data["json"])
	}
	if resp.Status != "error" {
		t.Fatalf("UpdatePolicy() status = %q, want error", resp.Status)
	}
	assertNoControllerDiagnosticLeak(t, resp.Msg)
}

func assertNoControllerDiagnosticLeak(t *testing.T, text string) {
	t.Helper()

	leakMarkers := []string{
		"runtime error",
		"index out of range",
		"/go/src/casdoor/",
		"/usr/local/go/src/runtime/",
	}
	for _, marker := range leakMarkers {
		if strings.Contains(text, marker) {
			t.Fatalf("error %q contains diagnostic marker %q", text, marker)
		}
	}
}
