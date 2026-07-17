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
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestCasP3ProxyValidateRejectsLookalikeServiceURL(t *testing.T) {
	const issuedService = "https://example.test/callback"
	const lookalikeService = "https://example.test/callback.attacker.test/collect"

	ticket := object.StoreCasTokenForProxyTicket(&object.CasAuthenticationSuccess{
		User: "alice",
		Attributes: &object.CasAttributes{
			Email: "alice@acme.example.com",
			Phone: "10000000001",
		},
	}, issuedService, "acme/alice")

	query := url.Values{}
	query.Set("service", lookalikeService)
	query.Set("ticket", ticket)
	query.Set("format", "json")

	req := httptest.NewRequest(http.MethodGet, "/cas/acme/app-acme/serviceValidate?"+query.Encode(), nil)
	rr := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(rr, req)

	controller := &RootController{}
	controller.Init(ctx, "RootController", "CasP3ProxyValidate", controller)
	controller.CasP3ProxyValidate()

	var response object.CasServiceResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode CAS response %q: %v", rr.Body.String(), err)
	}
	if response.Success != nil {
		t.Fatalf("lookalike service URL validated as user %q, want INVALID_SERVICE", response.Success.User)
	}
	if response.Failure == nil || response.Failure.Code != InvalidService {
		t.Fatalf("failure = %#v, want code %q", response.Failure, InvalidService)
	}
}
