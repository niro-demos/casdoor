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
	"sync"
	"testing"
	_ "unsafe"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

//go:linkname casServiceTickets github.com/casdoor/casdoor/object.stToServiceResponse
var casServiceTickets sync.Map

const (
	casIssuedService   = "https://trusted.example/callback"
	casAttackerService = "https://trusted.example/callback.attacker.invalid/collect"
)

func TestCasP3ProxyValidateRequiresExactIssuedService(t *testing.T) {
	exact := validateCasService(t, "ST-exact-service", casIssuedService, casIssuedService)
	if exact.Success == nil {
		t.Fatalf("exact issued service returned no success: failure=%+v", exact.Failure)
	}
	if exact.Success.User != "alice" {
		t.Fatalf("exact issued service user = %q, want alice", exact.Success.User)
	}
	if exact.Failure != nil {
		t.Fatalf("exact issued service returned unexpected failure: %+v", exact.Failure)
	}

	prefixOnly := validateCasService(t, "ST-prefix-only-service", casIssuedService, casAttackerService)
	if prefixOnly.Success != nil {
		t.Fatalf("prefix-only service unexpectedly validated user %q", prefixOnly.Success.User)
	}
	if prefixOnly.Failure == nil {
		t.Fatal("prefix-only service returned no failure")
	}
	if prefixOnly.Failure.Code != InvalidService {
		t.Fatalf("prefix-only service failure code = %q, want %q", prefixOnly.Failure.Code, InvalidService)
	}
}

func validateCasService(t *testing.T, ticket string, issuedService string, requestedService string) object.CasServiceResponse {
	t.Helper()

	casServiceTickets.Store(ticket, &object.CasAuthenticationSuccessWrapper{
		AuthenticationSuccess: &object.CasAuthenticationSuccess{
			User: "alice",
			Attributes: &object.CasAttributes{
				UserAttributes: &object.CasUserAttributes{},
			},
		},
		Service: issuedService,
		UserId:  "niro-alpha/alice",
	})

	values := url.Values{}
	values.Set("format", "json")
	values.Set("service", requestedService)
	values.Set("ticket", ticket)

	request := httptest.NewRequest(http.MethodGet, "/cas/niro-alpha/app-niro-alpha/p3/proxyValidate?"+values.Encode(), nil)
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, request)

	controller := &RootController{}
	controller.Init(ctx, "RootController", "CasP3ProxyValidate", controller)
	controller.CasP3ProxyValidate()

	var response object.CasServiceResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode CAS response %q: %v", recorder.Body.String(), err)
	}
	return response
}
