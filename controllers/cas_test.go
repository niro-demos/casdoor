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
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// newCasProxyValidateRequest wires a RootController to a GET request with the
// given raw query string and calls it exactly like the beego router would
// for /cas/:organization/:application/p3/proxyValidate -- without needing a
// live HTTP server or a database: CAS ticket state lives entirely in an
// in-process sync.Map (see object.StoreCasTokenForProxyTicket /
// object.GetCasTokenByTicket), so this exercises the real production code
// path end to end.
func newCasProxyValidateRequest(rawQuery string) (*RootController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest("GET", "http://localhost:8000/cas/acme/app-acme/p3/proxyValidate?"+rawQuery, nil)
	rec := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(rec, req)

	c := &RootController{}
	c.Init(ctx, "RootController", "CasP3ProxyValidate", c)
	return c, rec
}

type casJSONResponse struct {
	Success *object.CasAuthenticationSuccess `json:"Success"`
	Failure *object.CasAuthenticationFailure `json:"Failure"`
}

func parseCasResponse(t *testing.T, rec *httptest.ResponseRecorder) casJSONResponse {
	t.Helper()
	var resp casJSONResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not parse CAS response body %q: %v", rec.Body.String(), err)
	}
	return resp
}

// TestCasP3ProxyValidate_ServiceMustMatchExactly is the regression test for
// TC-891B7DA9: a CAS service ticket must only be redeemable by the exact
// service it was issued for, never by a string extension of it.
func TestCasP3ProxyValidate_ServiceMustMatchExactly(t *testing.T) {
	issuedService := "http://localhost:8000/callback"

	t.Run("exact service succeeds (positive control)", func(t *testing.T) {
		ticket := object.StoreCasTokenForProxyTicket(&object.CasAuthenticationSuccess{User: "alice"}, issuedService, "acme/alice")
		c, rec := newCasProxyValidateRequest(fmt.Sprintf("ticket=%s&service=%s&format=json",
			url.QueryEscape(ticket), url.QueryEscape(issuedService)))
		c.CasP3ProxyValidate()

		resp := parseCasResponse(t, rec)
		if resp.Success == nil {
			t.Fatalf("environment unhealthy: exact-service redemption did not succeed, got failure=%+v body=%s", resp.Failure, rec.Body.String())
		}
	})

	t.Run("unrelated service is rejected (negative control)", func(t *testing.T) {
		ticket := object.StoreCasTokenForProxyTicket(&object.CasAuthenticationSuccess{User: "alice"}, issuedService, "acme/alice")
		c, rec := newCasProxyValidateRequest(fmt.Sprintf("ticket=%s&service=%s&format=json",
			url.QueryEscape(ticket), url.QueryEscape("http://evil.example.com/steal")))
		c.CasP3ProxyValidate()

		resp := parseCasResponse(t, rec)
		if resp.Success != nil {
			t.Fatalf("environment unhealthy: a wholly unrelated service was accepted, got success=%+v", resp.Success)
		}
		if resp.Failure == nil || resp.Failure.Code != InvalidService {
			t.Fatalf("expected INVALID_SERVICE for an unrelated service, got failure=%+v body=%s", resp.Failure, rec.Body.String())
		}
	})

	t.Run("string-extended service is rejected", func(t *testing.T) {
		ticket := object.StoreCasTokenForProxyTicket(&object.CasAuthenticationSuccess{User: "alice"}, issuedService, "acme/alice")
		tamperedService := issuedService + ".attacker-controlled.example/steal"
		c, rec := newCasProxyValidateRequest(fmt.Sprintf("ticket=%s&service=%s&format=json",
			url.QueryEscape(ticket), url.QueryEscape(tamperedService)))
		c.CasP3ProxyValidate()

		resp := parseCasResponse(t, rec)
		if resp.Success != nil {
			t.Fatalf("invariant violated: ticket issued for service %q was redeemed by unregistered, string-extended service %q instead of being rejected; got success=%+v",
				issuedService, tamperedService, resp.Success)
		}
		if resp.Failure == nil || resp.Failure.Code != InvalidService {
			t.Fatalf("expected INVALID_SERVICE for a string-extended service, got failure=%+v body=%s", resp.Failure, rec.Body.String())
		}
	})
}

// TestCasP3ProxyValidate_RejectsUntrustedPgtUrlHost is the regression test
// for TC-7B55FAFC: the CAS proxy-callback pgtUrl must never cause the server
// to connect to an attacker-chosen network address (loopback here stands in
// for any internal/private destination).
func TestCasP3ProxyValidate_RejectsUntrustedPgtUrlHost(t *testing.T) {
	issuedService := "http://localhost:8000/callback"

	// Own throwaway raw TCP listener that this test process owns; the server
	// must never connect to it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start local listener: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	connCh := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		connCh <- struct{}{}
	}()

	ticket := object.StoreCasTokenForProxyTicket(&object.CasAuthenticationSuccess{User: "alice"}, issuedService, "acme/alice")
	pgtUrl := fmt.Sprintf("https://127.0.0.1:%d/ssrf-proof-owned-by-test", port)
	c, rec := newCasProxyValidateRequest(fmt.Sprintf("ticket=%s&service=%s&pgtUrl=%s&format=json",
		url.QueryEscape(ticket), url.QueryEscape(issuedService), url.QueryEscape(pgtUrl)))
	c.CasP3ProxyValidate()

	select {
	case <-connCh:
		t.Fatalf("invariant violated: server connected to the attacker-chosen pgtUrl host %s instead of rejecting it before dialing", pgtUrl)
	case <-time.After(2 * time.Second):
		// expected: no connection was ever attempted
	}

	resp := parseCasResponse(t, rec)
	if resp.Failure == nil || resp.Failure.Code != InvalidProxyCallback {
		t.Fatalf("expected INVALID_PROXY_CALLBACK for an untrusted pgtUrl host, got failure=%+v success=%+v body=%s",
			resp.Failure, resp.Success, rec.Body.String())
	}
}
