// Copyright 2025 The Casdoor Authors. All Rights Reserved.
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

//go:build !skipCi

package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// Regression test for TC-D7CC8BD9: POST /api/validate-coupon let any
// authenticated user validate (and thereby read the discount terms of)
// another organization's private coupon, because ValidateCoupon() discarded
// the caller's own organization and trusted the attacker-supplied
// req.Owner. The invariant under test: a caller must not be able to
// validate a coupon owned by an organization they don't belong to.

var couponTestDBOnce sync.Once

// initCouponTestDB brings up the real database connection the same way the
// existing object package tests do (see object/user_test.go), so this test
// exercises the controller against the project's own storage layer instead
// of a mock.
func initCouponTestDB(t *testing.T) {
	t.Helper()
	couponTestDBOnce.Do(func() {
		object.InitConfig()
	})
}

// callValidateCoupon builds a real beego request/response context (no HTTP
// server involved), wires it into a fresh ApiController exactly like the
// router would for POST /api/validate-coupon, sets the session identity the
// same way ApiFilter does (via the "currentUserId" context key that
// GetSessionUsername reads first), and invokes the handler under test.
func callValidateCoupon(t *testing.T, sessionUserId string, reqBody map[string]interface{}) *Response {
	t.Helper()

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	httpReq := httptest.NewRequest(http.MethodPost, "/api/validate-coupon", bytes.NewReader(bodyBytes))
	httpReq.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()

	beegoCtx := beegoContext.NewContext()
	beegoCtx.Reset(rw, httpReq)
	beegoCtx.Input.RequestBody = bodyBytes
	if sessionUserId != "" {
		beegoCtx.Input.SetData("currentUserId", sessionUserId)
	}

	c := &ApiController{}
	c.Init(beegoCtx, "ApiController", "ValidateCoupon", nil)

	c.ValidateCoupon()

	resp, ok := c.Data["json"].(*Response)
	if !ok {
		t.Fatalf("ValidateCoupon() did not produce a *controllers.Response, got %#v", c.Data["json"])
	}
	return resp
}

// seedTestCoupon inserts a private, active, universal-scope coupon owned by
// ownerOrg directly via the object layer (bypassing AddCoupon's controller,
// which is not part of this finding) and returns its code plus a cleanup
// function.
func seedTestCoupon(t *testing.T, ownerOrg string) (code string, cleanup func()) {
	t.Helper()

	ts := time.Now().UnixNano()
	name := fmt.Sprintf("coupon_regress_%d", ts)
	code = fmt.Sprintf("REGRESSSECRET%d", ts)

	coupon := &object.Coupon{
		Owner:        ownerOrg,
		Name:         name,
		DisplayName:  "Regression Secret Coupon",
		Code:         code,
		DiscountType: "Percentage",
		Discount:     0.5,
		MaxDiscount:  1000,
		Scope:        "universal",
		State:        "Active",
		Quantity:     100,
	}

	affected, err := object.AddCoupon(coupon)
	if err != nil || !affected {
		t.Fatalf("failed to seed test coupon: affected=%v err=%v", affected, err)
	}

	return code, func() {
		_, _ = object.DeleteCoupon(coupon)
	}
}

// TestValidateCoupon_RejectsCrossOrganization is the red case: a user
// belonging to a different organization than the coupon's owner must be
// rejected, never see the coupon's discount terms.
func TestValidateCoupon_RejectsCrossOrganization(t *testing.T) {
	initCouponTestDB(t)

	couponOwnerOrg := fmt.Sprintf("coupon_regress_org_owner_%d", time.Now().UnixNano())
	attackerOrg := fmt.Sprintf("coupon_regress_org_attacker_%d", time.Now().UnixNano())

	code, cleanup := seedTestCoupon(t, couponOwnerOrg)
	defer cleanup()

	// Attacker is a legitimately logged-in user, just not a member of
	// couponOwnerOrg.
	attackerSessionId := attackerOrg + "/attacker"

	resp := callValidateCoupon(t, attackerSessionId, map[string]interface{}{
		"owner":      couponOwnerOrg,
		"couponCode": code,
		"products":   []string{},
		"amount":     10,
		"currency":   "USD",
	})

	if resp.Status != "error" {
		t.Fatalf("invariant violated: a user from org %q was able to validate org %q's private coupon; status=%q data=%#v",
			attackerOrg, couponOwnerOrg, resp.Status, resp.Data)
	}

	if resp.Data != nil {
		t.Fatalf("invariant violated: rejected response still leaked coupon data: %#v", resp.Data)
	}
}

// TestValidateCoupon_AllowsSameOrganization is the paired positive control:
// a legitimate member of the coupon's own organization must still be able
// to validate it. This isolates the rejection above to the authorization
// check rather than a broken environment or an overly broad fix.
func TestValidateCoupon_AllowsSameOrganization(t *testing.T) {
	initCouponTestDB(t)

	ownerOrg := fmt.Sprintf("coupon_regress_org_member_%d", time.Now().UnixNano())
	code, cleanup := seedTestCoupon(t, ownerOrg)
	defer cleanup()

	memberSessionId := ownerOrg + "/member"

	resp := callValidateCoupon(t, memberSessionId, map[string]interface{}{
		"owner":      ownerOrg,
		"couponCode": code,
		"products":   []string{},
		"amount":     10,
		"currency":   "USD",
	})

	if resp.Status != "ok" {
		t.Fatalf("legitimate same-organization validation was rejected: status=%q msg=%q (environment/fix likely broken)", resp.Status, resp.Msg)
	}

	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected coupon data in successful response, got %#v", resp.Data)
	}
	couponData, ok := data["coupon"].(map[string]interface{})
	if !ok || couponData["displayName"] != "Regression Secret Coupon" {
		t.Fatalf("expected the seeded coupon's data in the response, got %#v", data)
	}
}
