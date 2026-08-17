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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestCasP3ProxyValidateRejectsServiceUrlPrefix(t *testing.T) {
	tests := []struct {
		name    string
		service string
	}{
		{
			name:    "attacker host as path suffix",
			service: "https://service.example/callback.attacker.invalid/steal",
		},
		{
			name:    "attacker host as userinfo authority",
			service: "https://service.example/callback@attacker.invalid/steal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ticket := object.StoreCasTokenForProxyTicket(&object.CasAuthenticationSuccess{
				User:       "alice",
				Attributes: &object.CasAttributes{Email: "alice@example.test"},
			}, "https://service.example/callback", "built-in/alice")

			body := validateCasTicket(t, ticket, tt.service)

			var response object.CasServiceResponse
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatalf("failed to decode CAS response %q: %v", string(body), err)
			}
			if response.Success != nil {
				t.Fatalf("service prefix %q authenticated user %q; want INVALID_SERVICE", tt.service, response.Success.User)
			}
			if response.Failure == nil || response.Failure.Code != InvalidService {
				t.Fatalf("service prefix %q returned %s; want %s", tt.service, summarizeCasFailure(response.Failure), InvalidService)
			}
		})
	}
}

func TestHandleLoggedInCasBranchValidatesServiceBeforeIssuingTicket(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file")
	}

	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "auth.go"))
	if err != nil {
		t.Fatal(err)
	}

	casBranch := string(source)
	start := strings.Index(casBranch, "form.Type == ResponseTypeCas")
	if start == -1 {
		t.Fatal("HandleLoggedIn CAS branch not found")
	}
	casBranch = casBranch[start:]
	end := strings.Index(casBranch, "\n\t} else {")
	if end == -1 {
		t.Fatal("HandleLoggedIn CAS branch end not found")
	}
	casBranch = casBranch[:end]

	checkIndex := strings.Index(casBranch, "object.CheckCasLogin(application, c.GetAcceptLanguage(), service)")
	generateIndex := strings.Index(casBranch, "object.GenerateCasToken(userId, service)")
	if generateIndex == -1 {
		t.Fatal("HandleLoggedIn CAS branch does not issue CAS tickets")
	}
	if checkIndex == -1 {
		t.Fatal("HandleLoggedIn CAS branch must validate the requested service with CheckCasLogin before issuing a CAS ticket")
	}
	if checkIndex > generateIndex {
		t.Fatal("HandleLoggedIn CAS branch validates the requested service after issuing the CAS ticket")
	}
}

func validateCasTicket(t *testing.T, ticket string, service string) []byte {
	t.Helper()

	values := url.Values{}
	values.Set("format", "json")
	values.Set("ticket", ticket)
	values.Set("service", service)

	request := httptest.NewRequest(http.MethodGet, "/cas/test/app/serviceValidate?"+values.Encode(), nil)
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, request)

	controller := &RootController{}
	controller.Init(ctx, "RootController", "CasP3ProxyValidate", nil)
	controller.CasP3ProxyValidate()

	if recorder.Code != http.StatusOK {
		t.Fatalf("CAS response HTTP status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

func summarizeCasFailure(failure *object.CasAuthenticationFailure) string {
	if failure == nil {
		return "no failure"
	}
	return failure.Code
}
