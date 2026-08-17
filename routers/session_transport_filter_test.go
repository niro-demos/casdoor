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
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

func TestSessionTransportFilterRejectsPlaintextLogin(t *testing.T) {
	recorder := runSessionTransportFilter(httptest.NewRequest(http.MethodPost, "http://example.test/api/login", nil))

	if recorder.Code != http.StatusUpgradeRequired {
		t.Fatalf("expected HTTP login to be rejected with 426, got %d", recorder.Code)
	}
}

func TestSessionTransportFilterRejectsPlaintextSessionCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/api/get-account", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "captured-session"})

	recorder := runSessionTransportFilter(req)

	if recorder.Code != http.StatusUpgradeRequired {
		t.Fatalf("expected HTTP session replay to be rejected with 426, got %d", recorder.Code)
	}
}

func TestSessionTransportFilterAllowsHttpsSessionTraffic(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/api/get-account", nil)
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-session"})

	recorder := runSessionTransportFilter(req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected HTTPS session traffic to continue through the filter, got %d", recorder.Code)
	}
}

func TestSessionTransportFilterAllowsPlaintextNonSessionTraffic(t *testing.T) {
	recorder := runSessionTransportFilter(httptest.NewRequest(http.MethodGet, "http://example.test/api/get-app-login", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected unauthenticated HTTP traffic to continue through the filter, got %d", recorder.Code)
	}
}

func runSessionTransportFilter(req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(recorder, req)

	SessionTransportFilter(ctx)

	return recorder
}
