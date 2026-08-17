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

//go:build !skipCi

package controllers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

// Invariant under test (TC-D16CF882): a user must only be able to
// validate/preview coupon codes that belong to their own organization.
// Coupon existence, discount percentage/amount, scope, and display name for
// another tenant's coupons must not be disclosed to users outside that
// tenant, regardless of the `owner` value they supply in the request body.

var initCouponTestApp sync.Once

// bootApp brings up enough of the real Casdoor server (DB + routes + authz
// policy) in-process to exercise the actual HTTP handler for POST
// /api/validate-coupon, exactly as it runs in production. It mirrors the
// relevant subset of main.go's startup sequence.
func bootApp(t *testing.T) *httptest.Server {
	t.Helper()

	initCouponTestApp.Do(func() {
		// Mirror main.go's session setup, using the in-memory provider so
		// the test has no filesystem/Redis dependency. Must happen before
		// web.InitBeegoBeforeTest below, which is what actually wires up
		// beego's session manager (registerSession hook).
		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.BConfig.WebConfig.Session.SessionProviderConfig = ""
		web.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24 * 30
		web.BConfig.WebConfig.Session.SessionGCMaxLifetime = int64(3600 * 24 * 30)

		// web.InitBeegoBeforeTest is beego's own test bootstrap: it loads
		// the app config and runs the same startup hooks that web.Run()
		// would (session/mime/template/admin/gzip). Using httptest against
		// web.BeeApp.Handlers directly (below) skips web.Run(), so this is
		// required or the session manager stays nil.
		web.InitBeegoBeforeTest("../conf/app.conf")

		object.InitAdapter() // connects to the DB configured in ../conf/app.conf
		object.CreateTables()
		object.InitDb()          // idempotent: seeds the built-in org/user/model/enforcer if missing
		authz.InitApi()          // (re)loads the built-in casbin policy, including "POST /api/validate-coupon" for authenticated users
		object.InitUserManager() // wires up the user/group casbin enforcer used by DeleteUser during cleanup
		routers.InitAPI()        // registers all routes, including /api/validate-coupon and /api/login
	})

	return httptest.NewServer(web.BeeApp.Handlers)
}

type apiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func newHTTPClient(withJar bool) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if withJar {
		jar, _ := cookiejar.New(nil)
		c.Jar = jar
	}
	return c
}

func doPostJSON(t *testing.T, client *http.Client, url string, body map[string]interface{}) apiResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out apiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

// couponTestFixture seeds two unrelated organizations: OwnerOrg, which owns
// a coupon that must stay private to it, and CallerOrg, whose user attempts
// to validate that coupon by supplying OwnerOrg's name as `owner`.
// CallerOrg also owns its own coupon, used to prove the fix doesn't break
// legitimate same-tenant validation.
type couponTestFixture struct {
	OwnerOrg      string
	CallerOrg     string
	CallerApp     string
	CallerName    string
	CallerPass    string
	ForeignCode   string // code of the coupon owned by OwnerOrg (must not be disclosable to CallerOrg's user)
	OwnCouponCode string // code of the coupon owned by CallerOrg itself (must remain usable by its own user)
}

func setupCouponFixture(t *testing.T) couponTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	ownerOrgName := "sec-coupon-owner-org-" + suffix
	callerOrgName := "sec-coupon-caller-org-" + suffix
	callerAppName := "sec-coupon-caller-app-" + suffix
	callerName := "coupon-caller"
	callerPass := "NiroTestPass123!"
	foreignCouponName := "foreign-coupon-" + suffix
	foreignCode := "FOREIGNCODE" + suffix
	ownCouponName := "own-coupon-" + suffix
	ownCode := "OWNCODE" + suffix

	ownerOrg := &object.Organization{
		Owner:           "admin",
		Name:            ownerOrgName,
		CreatedTime:     time.Now().Format(time.RFC3339),
		DisplayName:     "Security Test Coupon Owner Org " + suffix,
		PasswordType:    "plain",
		PasswordOptions: []string{"AtLeast6"},
		CountryCodes:    []string{"US"},
		Tags:            []string{},
		Languages:       []string{"en"},
		AccountItems:    object.GetDefaultAccountItems(),
	}
	if _, err := object.AddOrganization(ownerOrg); err != nil {
		t.Fatalf("failed to create coupon-owner test organization: %v", err)
	}

	callerOrg := &object.Organization{
		Owner:           "admin",
		Name:            callerOrgName,
		CreatedTime:     time.Now().Format(time.RFC3339),
		DisplayName:     "Security Test Coupon Caller Org " + suffix,
		PasswordType:    "plain",
		PasswordOptions: []string{"AtLeast6"},
		CountryCodes:    []string{"US"},
		Tags:            []string{},
		Languages:       []string{"en"},
		AccountItems:    object.GetDefaultAccountItems(),
	}
	if _, err := object.AddOrganization(callerOrg); err != nil {
		t.Fatalf("failed to create caller test organization: %v", err)
	}

	callerApp := &object.Application{
		Owner:               "admin",
		Name:                callerAppName,
		CreatedTime:         time.Now().Format(time.RFC3339),
		DisplayName:         "Security Test Coupon Caller App " + suffix,
		Organization:        callerOrgName,
		Cert:                "cert-built-in",
		EnablePassword:      true,
		SigninMethods:       []*object.SigninMethod{{Name: "Password", DisplayName: "Password", Rule: "All"}},
		Providers:           []*object.ProviderItem{}, // no captcha provider wired up -> captcha check is skipped
		RedirectUris:        []string{},
		Tags:                []string{},
		TokenFormat:         "JWT",
		TokenFields:         []string{},
		ExpireInHours:       168,
		FormOffset:          2,
		CookieExpireInHours: 720,
	}
	if _, err := object.AddApplication(callerApp); err != nil {
		t.Fatalf("failed to create caller test application: %v", err)
	}

	caller := &object.User{
		Owner:             callerOrgName,
		Name:              callerName,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          callerPass,
		DisplayName:       "Coupon Caller",
		Email:             "coupon-caller-" + suffix + "@example.com",
		SignupApplication: callerAppName,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(caller, "en"); err != nil {
		t.Fatalf("failed to create caller test user: %v", err)
	}

	foreignCoupon := &object.Coupon{
		Owner:        ownerOrgName,
		Name:         foreignCouponName,
		CreatedTime:  time.Now().Format(time.RFC3339),
		DisplayName:  "Secret Owner-Org Coupon " + suffix,
		Code:         foreignCode,
		DiscountType: "percentage",
		Discount:     42,
		MaxDiscount:  999,
		Scope:        "universal",
		State:        "Active",
		StartTime:    "2020-01-01T00:00:00Z",
		ExpireTime:   "2099-01-01T00:00:00Z",
	}
	if _, err := object.AddCoupon(foreignCoupon); err != nil {
		t.Fatalf("failed to create foreign test coupon: %v", err)
	}

	ownCoupon := &object.Coupon{
		Owner:        callerOrgName,
		Name:         ownCouponName,
		CreatedTime:  time.Now().Format(time.RFC3339),
		DisplayName:  "Caller's Own Coupon " + suffix,
		Code:         ownCode,
		DiscountType: "percentage",
		Discount:     15,
		MaxDiscount:  500,
		Scope:        "universal",
		State:        "Active",
		StartTime:    "2020-01-01T00:00:00Z",
		ExpireTime:   "2099-01-01T00:00:00Z",
	}
	if _, err := object.AddCoupon(ownCoupon); err != nil {
		t.Fatalf("failed to create caller-owned test coupon: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteCoupon(foreignCoupon)
		_, _ = object.DeleteCoupon(ownCoupon)
		_, _ = object.DeleteUser(caller)
		_, _ = object.DeleteApplication(callerApp)
		_, _ = object.DeleteOrganization(callerOrg)
		_, _ = object.DeleteOrganization(ownerOrg)
	})

	return couponTestFixture{
		OwnerOrg:      ownerOrgName,
		CallerOrg:     callerOrgName,
		CallerApp:     callerAppName,
		CallerName:    callerName,
		CallerPass:    callerPass,
		ForeignCode:   foreignCode,
		OwnCouponCode: ownCode,
	}
}

// TestValidateCouponRejectsCrossTenantOwner is the regression test for
// TC-D16CF882. It must fail (red) on the unfixed controllers/coupon.go,
// where ValidateCoupon() trusts the client-supplied req.Owner instead of the
// caller's own session-resolved organization, letting an authenticated user
// in one org disclose and validate another org's coupon by supplying that
// org's name as `owner`.
func TestValidateCouponRejectsCrossTenantOwner(t *testing.T) {
	server := bootApp(t)
	defer server.Close()

	fx := setupCouponFixture(t)
	caller := newHTTPClient(true)

	loginResp := doPostJSON(t, caller, server.URL+"/api/login", map[string]interface{}{
		"username":     fx.CallerName,
		"password":     fx.CallerPass,
		"organization": fx.CallerOrg,
		"application":  fx.CallerApp,
		"signinMethod": "Password",
		"type":         "login",
	})
	if loginResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: could not log in as the test caller user: %s", loginResp.Msg)
	}

	// Positive control: the caller validates a nonexistent code in HER OWN
	// org. Must be rejected with a clean "does not exist" style error,
	// proving the endpoint and fixture are healthy so a difference below is
	// the invariant breaking, not a broken environment.
	controlResp := doPostJSON(t, caller, server.URL+"/api/validate-coupon", map[string]interface{}{
		"owner":      fx.CallerOrg,
		"couponCode": "NOSUCHCODE-" + fx.ForeignCode,
		"products":   []string{},
		"amount":     100,
		"currency":   "USD",
	})
	if controlResp.Status != "error" {
		t.Fatalf("SETUP FAILURE: expected an error validating a nonexistent code in the caller's own org, got status=%s data=%s", controlResp.Status, controlResp.Data)
	}

	// Vulnerable path: caller supplies the unrelated owner org's name and its
	// real coupon code. Per the invariant, this must be rejected -- a user
	// must never be able to validate/preview a coupon belonging to another
	// tenant, no matter what `owner` they supply.
	crossResp := doPostJSON(t, caller, server.URL+"/api/validate-coupon", map[string]interface{}{
		"owner":      fx.OwnerOrg,
		"couponCode": fx.ForeignCode,
		"products":   []string{},
		"amount":     100,
		"currency":   "USD",
	})
	if crossResp.Status == "ok" {
		t.Fatalf("invariant violated: caller in org %q validated/disclosed a coupon owned by unrelated org %q by supplying owner=%q in the request body: %s",
			fx.CallerOrg, fx.OwnerOrg, fx.OwnerOrg, crossResp.Data)
	}
}

// TestValidateCouponAcceptsOwnTenantOwner proves the fix does not break the
// legitimate use case: a user validating a real, active coupon that belongs
// to their own organization must still succeed, even though the fix stops
// trusting the client-supplied `owner` field.
func TestValidateCouponAcceptsOwnTenantOwner(t *testing.T) {
	server := bootApp(t)
	defer server.Close()

	fx := setupCouponFixture(t)
	caller := newHTTPClient(true)

	loginResp := doPostJSON(t, caller, server.URL+"/api/login", map[string]interface{}{
		"username":     fx.CallerName,
		"password":     fx.CallerPass,
		"organization": fx.CallerOrg,
		"application":  fx.CallerApp,
		"signinMethod": "Password",
		"type":         "login",
	})
	if loginResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: could not log in as the test caller user: %s", loginResp.Msg)
	}

	ownResp := doPostJSON(t, caller, server.URL+"/api/validate-coupon", map[string]interface{}{
		"owner":      fx.CallerOrg,
		"couponCode": fx.OwnCouponCode,
		"products":   []string{},
		"amount":     100,
		"currency":   "USD",
	})
	if ownResp.Status != "ok" {
		t.Fatalf("behavior regression: caller could no longer validate a real, active coupon belonging to their own org: status=%s msg=%s", ownResp.Status, ownResp.Msg)
	}
}
