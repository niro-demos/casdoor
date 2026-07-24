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
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

func TestSecurityTransportFilterRejectsPlaintextLogin(t *testing.T) {
	ctx, recorder := newSecurityTransportContext(http.MethodPost, "http://example.com/api/login")

	SecurityTransportFilter(ctx)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected plaintext login to be rejected with %d, got %d", http.StatusForbidden, recorder.Code)
	}
	if !ctx.ResponseWriter.Started {
		t.Fatal("expected plaintext login rejection to stop handler execution")
	}
}

func TestSecurityTransportFilterRejectsPlaintextSessionReplay(t *testing.T) {
	ctx, recorder := newSecurityTransportContext(http.MethodGet, "http://example.com/api/get-account")
	ctx.Request.AddCookie(&http.Cookie{Name: "casdoor_session_id", Value: "captured-session"})

	SecurityTransportFilter(ctx)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected plaintext session replay to be rejected with %d, got %d", http.StatusForbidden, recorder.Code)
	}
	if !ctx.ResponseWriter.Started {
		t.Fatal("expected plaintext session replay rejection to stop handler execution")
	}
}

func TestSecurityTransportFilterAllowsForwardedHTTPSAuth(t *testing.T) {
	ctx, recorder := newSecurityTransportContext(http.MethodPost, "http://example.com/api/login")
	ctx.Request.Header.Set("X-Forwarded-Proto", "https")

	SecurityTransportFilter(ctx)

	if ctx.ResponseWriter.Started {
		t.Fatal("expected forwarded HTTPS login to continue to the handler")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected no response to be written by the filter, got %d", recorder.Code)
	}
}

func newSecurityTransportContext(method string, target string) (*context.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, target, nil)
	recorder := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(recorder, req)
	return ctx, recorder
}
