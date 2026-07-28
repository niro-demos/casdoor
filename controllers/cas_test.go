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
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// --- TC-27C4AC97: pgtUrl host-ownership / SSRF guard -----------------------

// TestValidatePgtCallbackTargetRejectsHostMismatch is a regression test for
// TC-27C4AC97: a pgtUrl whose host has no relationship to the service the
// ticket was actually issued for must be rejected before any outbound
// request is made, exactly like the pre-existing ownership check already
// applied to the "service" parameter in CasP3ProxyValidate.
func TestValidatePgtCallbackTargetRejectsHostMismatch(t *testing.T) {
	issuedService := "http://198.51.100.10:9000/callback"
	cases := []string{
		"https://203.0.113.5/",                      // unrelated host entirely (stand-in for example.com in the live PoC)
		"https://169.254.169.254/latest/meta-data/", // cloud metadata address
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			pgtUrlObj, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("test setup: could not parse %q: %v", raw, err)
			}
			if err := validatePgtCallbackTarget(pgtUrlObj, issuedService); err == nil {
				t.Fatalf("validatePgtCallbackTarget(%q, issuedService=%q) = nil error, want rejection: host has no relationship to the registered service", raw, issuedService)
			}
		})
	}
}

// TestValidatePgtCallbackTargetAllowsMatchingPublicHost is the positive
// control: a pgtUrl whose host genuinely matches the service the ticket was
// issued for, and which resolves to a public address, must be allowed.
// Uses literal IPs (TEST-NET-2, RFC 5737) so the test needs no real DNS
// resolution and is not "private/loopback/link-local" per util.IsIntranetIp.
func TestValidatePgtCallbackTargetAllowsMatchingPublicHost(t *testing.T) {
	issuedService := "http://198.51.100.10:9000/callback"
	pgtUrlObj, err := url.Parse("https://198.51.100.10/pgtcallback")
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	if err := validatePgtCallbackTarget(pgtUrlObj, issuedService); err != nil {
		t.Fatalf("validatePgtCallbackTarget matching public host: unexpected error: %v, want the matching, public-looking host to be allowed", err)
	}
}

// TestValidatePgtCallbackTargetRejectsIntranetEvenWhenHostMatches is the
// defense-in-depth half of TC-27C4AC97's remediation: even when the pgtUrl
// host string matches the registered service's host, the destination must
// not resolve to a loopback/link-local/private address. This closes DNS
// rebinding on an otherwise allow-listed hostname (relevant when the
// service itself was registered as an attacker-controlled domain name).
func TestValidatePgtCallbackTargetRejectsIntranetEvenWhenHostMatches(t *testing.T) {
	issuedService := "http://127.0.0.1:9000/callback"
	pgtUrlObj, err := url.Parse("https://127.0.0.1/pgtcallback")
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	if err := validatePgtCallbackTarget(pgtUrlObj, issuedService); err == nil {
		t.Fatalf("validatePgtCallbackTarget(loopback, matching loopback service) = nil error, want rejection of the intranet destination")
	}
}

// TestSafeCasProxyDialContextBlocksLoopbackDestination is the TOCTOU/DNS-
// rebinding regression test for the actual dial used to perform the pgtUrl
// callback: even if a host looked safe at validation time, the transport
// that dials the connection must independently refuse a loopback/private
// destination. A direct plain dial is used as a positive control to prove
// the address really was reachable, so the rejection is provably the guard.
func TestSafeCasProxyDialContextBlocksLoopbackDestination(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("test setup: could not parse httptest server URL: %v", err)
	}
	addr := parsed.Host

	directConn, dialErr := net.Dial("tcp", addr)
	if dialErr != nil {
		t.Fatalf("test setup: httptest server not reachable via a plain dial: %v", dialErr)
	}
	_ = directConn.Close()

	conn, err := safeCasProxyDialContext(context.Background(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("safeCasProxyDialContext(%q) succeeded dialing a loopback address, want rejection", addr)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("safeCasProxyDialContext dialed the loopback server (hits=%d); it must reject before connecting", hits)
	}
}

// --- TC-4C22EBF1: no PGT leak on callback failure ---------------------------

// fakeRoundTripper lets tests control exactly what the pgtUrl callback
// "sees" as a response/error without any real network access, and records
// the request that was made so tests can inspect exactly what was sent to
// the callback (e.g. the pgtId/pgtIou query parameters).
type fakeRoundTripper struct {
	resp    *http.Response
	err     error
	lastReq *http.Request
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

// TestPerformPgtCallbackDoesNotLeakUnderlyingError is a regression test for
// the disclosure half of TC-4C22EBF1: when the transport fails, the
// underlying error (which for net/http embeds the full request URL -
// including the pgtId/pgtIou query parameters added just before the
// request was built) must never be returned/echoed to the CAS client.
func TestPerformPgtCallbackDoesNotLeakUnderlyingError(t *testing.T) {
	secretPgt := "PGT-super-secret-id"
	secretIou := "PGTIOU-super-secret-iou"
	pgtUrlObj, _ := url.Parse("https://198.51.100.10/pgtcallback")

	// Mirrors the real net/http transport error shape: *url.Error whose
	// Error() text embeds the full dialed URL.
	transportErr := &url.Error{
		Op:  "Get",
		URL: fmt.Sprintf("https://198.51.100.10/pgtcallback?pgtId=%s&pgtIou=%s", secretPgt, secretIou),
		Err: fmt.Errorf("dial tcp 198.51.100.10:443: connect: connection refused"),
	}
	client := &http.Client{Transport: &fakeRoundTripper{err: transportErr}}

	err := performPgtCallback(client, pgtUrlObj, secretPgt, secretIou)
	if err == nil {
		t.Fatalf("performPgtCallback() = nil error, want an error since the transport failed")
	}
	if strings.Contains(err.Error(), secretPgt) || strings.Contains(err.Error(), secretIou) {
		t.Fatalf("performPgtCallback() error leaks the pgt id/iou: %q", err.Error())
	}
	if strings.Contains(err.Error(), "198.51.100.10") {
		t.Fatalf("performPgtCallback() error leaks the callback URL: %q", err.Error())
	}
}

// TestPerformPgtCallbackRejectsNonSuccessStatus confirms a non-2xx/3xx
// response is also treated as failure without leaking any response detail.
func TestPerformPgtCallbackRejectsNonSuccessStatus(t *testing.T) {
	pgtUrlObj, _ := url.Parse("https://198.51.100.10/pgtcallback")
	resp := &http.Response{StatusCode: http.StatusInternalServerError, Body: http.NoBody}
	client := &http.Client{Transport: &fakeRoundTripper{resp: resp}}

	if err := performPgtCallback(client, pgtUrlObj, "PGT-x", "PGTIOU-x"); err == nil {
		t.Fatalf("performPgtCallback() = nil error for a 500 response, want rejection")
	}
}

// TestPerformPgtCallbackSucceedsOn2xx confirms the positive control: a
// genuine 2xx response is accepted.
func TestPerformPgtCallbackSucceedsOn2xx(t *testing.T) {
	pgtUrlObj, _ := url.Parse("https://198.51.100.10/pgtcallback")
	resp := &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}
	client := &http.Client{Transport: &fakeRoundTripper{resp: resp}}

	if err := performPgtCallback(client, pgtUrlObj, "PGT-x", "PGTIOU-x"); err != nil {
		t.Fatalf("performPgtCallback() unexpected error for a 200 response: %v", err)
	}
}

// --- Full-flow regression: CasP3ProxyValidate --------------------------------

// newCasTestController builds a RootController wired to a real (but fully
// in-memory, no DB) beego context for the given raw query string, so
// CasP3ProxyValidate can be invoked exactly as it would be over HTTP.
func newCasTestController(rawQuery string) (*RootController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/cas/niro-test/app-niro-test/serviceValidate?"+rawQuery, nil)
	w := httptest.NewRecorder()

	ctx := beegoContext.NewContext()
	ctx.Reset(w, req)

	c := &RootController{}
	c.Init(ctx, "RootController", "CasP3ProxyValidate", nil)
	return c, w
}

// TestCasP3ProxyValidateRejectsMismatchedPgtUrlHost is the full-stack
// regression test for TC-27C4AC97: a validly-ticketed caller supplying a
// pgtUrl for a host unrelated to the registered service must get
// authenticationFailure, and the server must never have attempted the
// outbound callback.
func TestCasP3ProxyValidateRejectsMismatchedPgtUrlHost(t *testing.T) {
	service := "http://198.51.100.10:9000/callback"
	token := &object.CasAuthenticationSuccess{User: "alice", ProxyGrantingTicket: "PGTIOU-fixed"}
	ticket := object.StoreCasTokenForProxyTicket(token, service, "niro-test/alice")

	attackerPgtUrl := "https://203.0.113.5/collect"
	q := url.Values{}
	q.Set("service", service)
	q.Set("ticket", ticket)
	q.Set("pgtUrl", attackerPgtUrl)

	c, w := newCasTestController(q.Encode())
	c.CasP3ProxyValidate()

	body := w.Body.String()
	if !strings.Contains(body, "authenticationFailure") || !strings.Contains(body, InvalidProxyCallback) {
		t.Fatalf("expected authenticationFailure/%s for a pgtUrl host unrelated to the registered service, got: %s", InvalidProxyCallback, body)
	}
	if strings.Contains(body, "authenticationSuccess") {
		t.Fatalf("server accepted a pgtUrl callback to an unrelated host: %s", body)
	}
}

// TestCasP3ProxyValidateDoesNotStoreOrLeakPgtOnCallbackFailure is the
// full-stack regression test for TC-4C22EBF1: when the pgtUrl callback
// fails (even though its host matches the registered service, so it passes
// the ownership/SSRF guard), the response must be a generic failure with no
// pgtId/pgtIou disclosed, and the transport must never even be reachable
// for storing an unconfirmed PGT to matter. The callback transport is
// swapped for a fake one so this needs no real network access.
func TestCasP3ProxyValidateDoesNotStoreOrLeakPgtOnCallbackFailure(t *testing.T) {
	service := "http://198.51.100.20:9000/callback"
	token := &object.CasAuthenticationSuccess{User: "alice", ProxyGrantingTicket: "PGTIOU-fixed-2"}
	ticket := object.StoreCasTokenForProxyTicket(token, service, "niro-test/alice")

	matchingPgtUrl := "https://198.51.100.20/pgtcallback"

	transportErr := fmt.Errorf("dial tcp 198.51.100.20:443: i/o timeout")
	frt := &fakeRoundTripper{err: transportErr}
	oldClient := casProxyCallbackClient
	casProxyCallbackClient = &http.Client{Transport: frt}
	defer func() { casProxyCallbackClient = oldClient }()

	q := url.Values{}
	q.Set("service", service)
	q.Set("ticket", ticket)
	q.Set("pgtUrl", matchingPgtUrl)

	c, w := newCasTestController(q.Encode())
	c.CasP3ProxyValidate()

	body := w.Body.String()
	if !strings.Contains(body, "authenticationFailure") || !strings.Contains(body, InvalidProxyCallback) {
		t.Fatalf("expected authenticationFailure/%s when the callback fails, got: %s", InvalidProxyCallback, body)
	}
	if strings.Contains(body, "pgtId") || strings.Contains(body, "PGT-") || strings.Contains(body, "198.51.100.20:443") {
		t.Fatalf("response leaks callback/transport detail (pgtId or dial error) on callback failure: %s", body)
	}

	// The request the fake transport received still carried a pgtId (proving
	// a PGT id was generated and sent to the callback, per the CAS
	// protocol) - but it must not have been activated/stored, so redeeming
	// it must fail. We recover it here only because the test controls the
	// transport; a real network attacker never sees this value because the
	// callback never succeeded.
	if frt.lastReq == nil {
		t.Fatalf("test setup: the callback transport was never invoked")
	}
	sentPgt := frt.lastReq.URL.Query().Get("pgtId")
	if sentPgt == "" {
		t.Fatalf("test setup: no pgtId was sent to the callback")
	}
	if ok, _, _, _ := object.GetCasTokenByPgt(sentPgt); ok {
		t.Fatalf("GetCasTokenByPgt(%q) = true after a failed pgtUrl callback; the PGT must not be stored/redeemable until the callback succeeds", sentPgt)
	}
}

// TestCasP3ProxyValidateStoresPgtOnlyAfterCallbackSucceeds is the positive
// control for the test above: once the callback succeeds, the PGT that was
// sent to it must become valid and redeemable exactly once.
func TestCasP3ProxyValidateStoresPgtOnlyAfterCallbackSucceeds(t *testing.T) {
	service := "http://198.51.100.30:9000/callback"
	token := &object.CasAuthenticationSuccess{User: "alice", ProxyGrantingTicket: "PGTIOU-fixed-3"}
	ticket := object.StoreCasTokenForProxyTicket(token, service, "niro-test/alice")

	matchingPgtUrl := "https://198.51.100.30/pgtcallback"

	frt := &fakeRoundTripper{resp: &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}}
	oldClient := casProxyCallbackClient
	casProxyCallbackClient = &http.Client{Transport: frt}
	defer func() { casProxyCallbackClient = oldClient }()

	q := url.Values{}
	q.Set("service", service)
	q.Set("ticket", ticket)
	q.Set("pgtUrl", matchingPgtUrl)

	c, w := newCasTestController(q.Encode())
	c.CasP3ProxyValidate()

	body := w.Body.String()
	if !strings.Contains(body, "authenticationSuccess") {
		t.Fatalf("expected authenticationSuccess when the callback succeeds, got: %s", body)
	}

	if frt.lastReq == nil {
		t.Fatalf("test setup: the callback transport was never invoked")
	}
	sentPgt := frt.lastReq.URL.Query().Get("pgtId")
	if sentPgt == "" {
		t.Fatalf("test setup: no pgtId was sent to the callback")
	}
	ok, _, gotService, gotUserId := object.GetCasTokenByPgt(sentPgt)
	if !ok {
		t.Fatalf("GetCasTokenByPgt(%q) = false after a successful pgtUrl callback; the PGT must be redeemable", sentPgt)
	}
	if gotService != service || gotUserId != "niro-test/alice" {
		t.Fatalf("GetCasTokenByPgt(%q) returned unexpected data: service=%q userId=%q", sentPgt, gotService, gotUserId)
	}
}
