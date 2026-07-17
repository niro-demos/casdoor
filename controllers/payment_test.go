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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	beegoCtx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// TestMain wires up an isolated sqlite-backed database for the controllers
// package tests, mirroring how niro/harness/start.sh boots Casdoor against
// sqlite for local testing (env-var overrides of conf/app.conf, read by
// conf.GetConfigString) instead of the mysql instance app.conf points at by
// default.
func TestMain(m *testing.M) {
	dbFile := filepath.Join(os.TempDir(), fmt.Sprintf("casdoor-controllers-test-%d.db", time.Now().UnixNano()))
	defer os.Remove(dbFile)

	os.Setenv("driverName", "sqlite")
	os.Setenv("dataSourceName", "file:"+dbFile+"?cache=shared")
	os.Setenv("dbName", "casdoor")

	// object.InitFlag() defines and parses the -createDatabase/-config flags
	// (both left at their defaults below, i.e. createDatabase=false); it's
	// what main.go calls before object.InitAdapter() / object.CreateTables()
	// so that CreateTables() skips the mysql-only
	// "CREATE DATABASE IF NOT EXISTS" statement, which sqlite rejects. Its
	// default -config path ("conf/app.conf") is relative to a process
	// launched from the repo root, so pass the "../conf/app.conf" path that
	// resolves from this package's test working directory instead; replace
	// os.Args for the call so `go test`'s own flags (-test.run, etc.) don't
	// reach flag.Parse().
	oldArgs := os.Args
	os.Args = []string{oldArgs[0], "-config=../conf/app.conf"}
	object.InitFlag()
	os.Args = oldArgs

	object.InitAdapter()
	object.CreateTables()

	os.Exit(m.Run())
}

// newTestApiController builds an ApiController wired to a fresh httptest
// request/recorder pair and stamps ctxUser as the authenticated caller via
// the same "currentUserId" context key routers/authz_filter.go sets after a
// real login, so GetSessionUsername()/IsAdmin() behave the way they do for
// an authenticated request without standing up sessions or HTTP middleware.
func newTestApiController(method, target, ctxUser string) (*ApiController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, target, nil)
	rw := httptest.NewRecorder()

	ctx := beegoCtx.NewContext()
	ctx.Reset(rw, req)
	if ctxUser != "" {
		ctx.Input.SetData("currentUserId", ctxUser)
	}

	c := &ApiController{}
	c.Init(ctx, "ApiController", "InvoicePayment", nil)

	return c, rw
}

func decodeResponse(t *testing.T, rw *httptest.ResponseRecorder) Response {
	t.Helper()
	// Decode only the first JSON value. InvoicePayment() has a pre-existing,
	// separate bug on its provider-lookup error path: it calls
	// c.ResponseError(...) without returning, so ServeJSON() runs a second
	// time and a second JSON object gets appended to the body. A real
	// net/http server silently truncates writes past the first response's
	// declared Content-Length, which is why the live target in the finding
	// only ever showed one clean JSON object; httptest.ResponseRecorder
	// doesn't truncate, so mimic what a real client sees by decoding just
	// the leading value instead of failing on the trailing bytes.
	var resp Response
	if err := json.NewDecoder(bytes.NewReader(rw.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatalf("could not decode response body %q: %v", rw.Body.String(), err)
	}
	return resp
}

// TestInvoicePaymentEnforcesOwnership is the regression test for
// TC-E7A86A1F: POST /api/invoice-payment must deny a non-owner the same way
// GET /api/get-payment already does (payment.Owner/payment.User compared
// against the caller), instead of running invoice generation against a
// record the caller does not own.
func TestInvoicePaymentEnforcesOwnership(t *testing.T) {
	paymentName := fmt.Sprintf("test-invoice-payment-%d", time.Now().UnixNano())
	payment := &object.Payment{
		Owner:       "acme",
		Name:        paymentName,
		DisplayName: "Test Product",
		Provider:    "",
		Type:        "Alipay",
		ProductName: "test-product",
		Detail:      "test",
		Currency:    "USD",
		Price:       11.11,
		User:        "acme-admin",
		State:       "Paid",
	}
	affected, err := object.AddPayment(payment)
	if err != nil {
		t.Fatalf("failed to seed payment: %v", err)
	}
	if !affected {
		t.Fatalf("seeding payment had no effect")
	}
	paymentId := "acme/" + paymentName

	t.Run("non-owner is denied (red case)", func(t *testing.T) {
		c, rw := newTestApiController("POST", "/api/invoice-payment?id="+paymentId, "acme/alice")
		c.InvoicePayment()

		resp := decodeResponse(t, rw)
		if resp.Status != "error" || resp.Msg != "Forbidden" {
			t.Fatalf(`invariant violated: non-owner "acme/alice" must be denied invoice generation on a payment owned by "acme/acme-admin" with {"status":"error","msg":"Forbidden"}, got status=%q msg=%q`, resp.Status, resp.Msg)
		}
	})

	t.Run("owner is not blocked by the ownership check (control)", func(t *testing.T) {
		c, rw := newTestApiController("POST", "/api/invoice-payment?id="+paymentId, "acme/acme-admin")
		c.InvoicePayment()

		resp := decodeResponse(t, rw)
		// The ownership check must not trip for the payment's own owner/user.
		// This seeded record has no payment provider configured, so the call
		// still errors -- but it must fail deeper in the handler than the
		// ownership gate, i.e. never with "Forbidden".
		if resp.Msg == "Forbidden" {
			t.Fatalf("owner %q was incorrectly denied by the ownership check: %+v", "acme/acme-admin", resp)
		}
	})
}
