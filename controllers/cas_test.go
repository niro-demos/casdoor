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
	"net/http/httptest"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func validateCasService(t *testing.T, issuedService, requestedService string) object.CasServiceResponse {
	t.Helper()

	success := &object.CasAuthenticationSuccess{User: "cas-user"}
	ticket := object.StoreCasTokenForProxyTicket(success, issuedService, "test/cas-user")
	req := httptest.NewRequest("GET", "/?ticket="+ticket+"&service="+requestedService+"&format=json", nil)
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, req)

	controller := &RootController{}
	controller.Init(ctx, "RootController", "CasP3ProxyValidate", nil)
	controller.CasP3ProxyValidate()

	var response object.CasServiceResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode CAS response: %v; body=%q", err, recorder.Body.String())
	}
	return response
}

func TestCasServiceValidationRequiresExactService(t *testing.T) {
	const issuedService = "https://service.example/app"

	t.Run("exact service is accepted", func(t *testing.T) {
		response := validateCasService(t, issuedService, issuedService)
		if response.Success == nil || response.Success.User != "cas-user" {
			t.Fatalf("exact service should succeed, got %+v", response)
		}
	})

	t.Run("different service sharing prefix is rejected", func(t *testing.T) {
		response := validateCasService(t, issuedService, "https://service.example/app.evil.com")
		if response.Success != nil {
			t.Fatalf("ticket for %q authenticated a different service sharing its prefix", issuedService)
		}
		if response.Failure == nil || response.Failure.Code != InvalidService {
			t.Fatalf("different service should fail with %s, got %+v", InvalidService, response)
		}
	})
}
