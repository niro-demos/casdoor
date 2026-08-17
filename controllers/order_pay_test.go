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

package controllers

// This is a live-target integration regression test for PlaceOrder(). It is
// not a hermetic unit test because PlaceOrder is a beego web.Controller method
// that reads its authenticated session (c.GetSessionUsername(), c.IsAdmin())
// straight off an HTTP request/response context that only exists inside a
// running server; there is no seam to construct that context in-process. The
// project's own object-package tests already assume a live, prepared backend
// (they call InitConfig() and hit a real database with no skip path); this
// test follows the same convention, one HTTP hop further out, against a
// server prepared the same way niro/harness/seed.sh prepares it: two
// organizations (niro-alpha, niro-beta), each with a tenant admin and a
// standard, non-admin user, reachable with the password below.
//
// Invariant under test: a buyer may only place orders inside their own
// organization's namespace, using that organization's own product inventory
// and coupon budget - never inside another organization's namespace, no
// matter what "owner" query parameter they send.
//
// Set CASDOOR_TEST_URL to point this at a different prepared instance; it
// defaults to the local niro harness target. The test skips (does not fail)
// when no such server is reachable, since most local `go test ./...` runs
// won't have the two-tenant fixture environment set up.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"testing"
	"time"
)

func testEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type placeOrderTestClient struct {
	t      *testing.T
	base   string
	client *http.Client
}

type placeOrderApiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type placeOrderOrderData struct {
	Owner      string  `json:"owner"`
	Name       string  `json:"name"`
	User       string  `json:"user"`
	Price      float64 `json:"price"`
	CouponName string  `json:"couponName"`
	State      string  `json:"state"`
}

func newPlaceOrderTestClient(t *testing.T, base string) *placeOrderTestClient {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &placeOrderTestClient{t: t, base: base, client: &http.Client{Jar: jar}}
}

func (c *placeOrderTestClient) doJSON(method, path string, body interface{}) *placeOrderApiResponse {
	c.t.Helper()

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal request body for %s: %v", path, err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, reqBody)
	if err != nil {
		c.t.Fatalf("build request for %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatalf("request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("read response body for %s: %v", path, err)
	}
	var parsed placeOrderApiResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		c.t.Fatalf("non-JSON response for %s (HTTP %d): %s", path, resp.StatusCode, string(raw))
	}
	return &parsed
}

func (c *placeOrderTestClient) login(org, app, username, password string) error {
	resp := c.doJSON(http.MethodPost, "/api/login", map[string]string{
		"application":  app,
		"organization": org,
		"username":     username,
		"password":     password,
		"signinMethod": "Password",
		"type":         "login",
	})
	if resp.Status != "ok" {
		return fmt.Errorf("login as %s/%s failed: %s", org, username, resp.Msg)
	}
	return nil
}

// TestPlaceOrderRejectsCrossTenantOwner is the regression test for
// TC-386C9A18: POST /api/place-order must reject a caller-supplied "owner"
// query parameter that does not match the authenticated caller's own
// organization (unless the caller is an admin), the same way the handler
// already rejects a mismatched "userName" override.
func TestPlaceOrderRejectsCrossTenantOwner(t *testing.T) {
	base := testEnv("CASDOOR_TEST_URL", "http://127.0.0.1:18000")

	healthResp, err := http.Get(base + "/api/health")
	if err != nil || healthResp.StatusCode != http.StatusOK {
		t.Skipf("no live, two-tenant-seeded Casdoor instance reachable at %s (set CASDOOR_TEST_URL, or run niro/harness/start.sh + seed.sh): %v", base, err)
	}
	healthResp.Body.Close()

	betaAdminOrg := testEnv("BETA_ADMIN_ORG", "niro-beta")
	betaAdminApp := testEnv("BETA_ADMIN_APP", "app-niro-beta")
	betaAdminUsername := testEnv("BETA_ADMIN_USERNAME", "admin")
	betaAdminPassword := testEnv("BETA_ADMIN_PASSWORD", "NiroPass123")

	alphaAdminOrg := testEnv("ALPHA_ADMIN_ORG", "niro-alpha")
	alphaAdminApp := testEnv("ALPHA_ADMIN_APP", "app-niro-alpha")
	alphaAdminUsername := testEnv("ALPHA_ADMIN_USERNAME", "admin")
	alphaAdminPassword := testEnv("ALPHA_ADMIN_PASSWORD", "NiroPass123")

	aliceOrg := testEnv("ALICE_ORG", "niro-alpha")
	aliceApp := testEnv("ALICE_APP", "app-niro-alpha")
	aliceUsername := testEnv("ALICE_USERNAME", "alice")
	alicePassword := testEnv("ALICE_PASSWORD", "NiroPass123")

	runID := fmt.Sprintf("tc386c9a18%d", time.Now().UnixNano()%1_000_000_000)
	betaProductName := "product_" + runID + "_beta"
	alphaProductName := "product_" + runID + "_alpha"
	couponName := "coupon_" + runID
	couponCode := fmt.Sprintf("TC386T%X", time.Now().UnixNano()%0xFFFFFF)

	betaAdmin := newPlaceOrderTestClient(t, base)
	alphaAdmin := newPlaceOrderTestClient(t, base)
	alice := newPlaceOrderTestClient(t, base)

	if err := betaAdmin.login(betaAdminOrg, betaAdminApp, betaAdminUsername, betaAdminPassword); err != nil {
		t.Skipf("could not log in as %s/%s (two-tenant fixture not seeded?): %v", betaAdminOrg, betaAdminUsername, err)
	}
	if err := alphaAdmin.login(alphaAdminOrg, alphaAdminApp, alphaAdminUsername, alphaAdminPassword); err != nil {
		t.Skipf("could not log in as %s/%s (two-tenant fixture not seeded?): %v", alphaAdminOrg, alphaAdminUsername, err)
	}
	if err := alice.login(aliceOrg, aliceApp, aliceUsername, alicePassword); err != nil {
		t.Skipf("could not log in as %s/%s (two-tenant fixture not seeded?): %v", aliceOrg, aliceUsername, err)
	}

	var createdBetaOrder, createdAlphaOrder string
	t.Cleanup(func() {
		if createdBetaOrder != "" {
			betaAdmin.doJSON(http.MethodPost, "/api/delete-order", map[string]string{"owner": betaAdminOrg, "name": createdBetaOrder})
		}
		if createdAlphaOrder != "" {
			alphaAdmin.doJSON(http.MethodPost, "/api/delete-order", map[string]string{"owner": alphaAdminOrg, "name": createdAlphaOrder})
		}
		betaAdmin.doJSON(http.MethodPost, "/api/delete-product", map[string]string{"owner": betaAdminOrg, "name": betaProductName})
		alphaAdmin.doJSON(http.MethodPost, "/api/delete-product", map[string]string{"owner": alphaAdminOrg, "name": alphaProductName})
		betaAdmin.doJSON(http.MethodPost, "/api/delete-coupon", map[string]string{"owner": betaAdminOrg, "name": couponName})
	})

	// Disposable fixtures, owned by this run, so the test never touches shared seeded data.
	if resp := betaAdmin.doJSON(http.MethodPost, "/api/add-product", map[string]interface{}{
		"owner": betaAdminOrg, "name": betaProductName, "displayName": "TC386C9A18 Beta Product",
		"price": 10, "quantity": 5, "sold": 0, "currency": "USD", "state": "Published",
		"providers": []string{"provider_payment_dummy"},
	}); resp.Status != "ok" {
		t.Fatalf("could not create disposable %s product: %s", betaAdminOrg, resp.Msg)
	}
	if resp := alphaAdmin.doJSON(http.MethodPost, "/api/add-product", map[string]interface{}{
		"owner": alphaAdminOrg, "name": alphaProductName, "displayName": "TC386C9A18 Alpha Product",
		"price": 10, "quantity": 5, "sold": 0, "currency": "USD", "state": "Published",
		"providers": []string{"provider_payment_dummy"},
	}); resp.Status != "ok" {
		t.Fatalf("could not create disposable %s product: %s", alphaAdminOrg, resp.Msg)
	}
	if resp := betaAdmin.doJSON(http.MethodPost, "/api/add-coupon", map[string]interface{}{
		"owner": betaAdminOrg, "name": couponName, "code": couponCode,
		"discountType": "percentage", "discount": 50, "scope": "universal",
		"quantity": 5, "maxUsagePerUser": 0, "state": "Active", "currency": "USD",
	}); resp.Status != "ok" {
		t.Fatalf("could not create disposable %s coupon: %s", betaAdminOrg, resp.Msg)
	}

	// Positive control: alice places a legitimate order inside her OWN organization.
	// Must succeed - proves the endpoint and the fixtures work normally, so a later
	// rejection is the invariant firing, not a broken environment.
	ctrlResp := alice.doJSON(http.MethodPost, "/api/place-order?owner="+alphaAdminOrg, map[string]interface{}{
		"productInfos": []map[string]interface{}{{"name": alphaProductName, "quantity": 1}},
	})
	if ctrlResp.Status != "ok" {
		t.Fatalf("harness sanity check failed: alice could not place a legitimate order in her own organization (%s): %s", alphaAdminOrg, ctrlResp.Msg)
	}
	var ctrlOrder placeOrderOrderData
	if err := json.Unmarshal(ctrlResp.Data, &ctrlOrder); err != nil || ctrlOrder.Owner != alphaAdminOrg {
		t.Fatalf("could not parse positive-control order: %s", string(ctrlResp.Data))
	}
	createdAlphaOrder = ctrlOrder.Name

	// The actual check: same alice session (no membership or role in niro-beta)
	// places an order with owner=niro-beta. Must be rejected.
	exploitResp := alice.doJSON(http.MethodPost, "/api/place-order?owner="+betaAdminOrg, map[string]interface{}{
		"productInfos": []map[string]interface{}{{"name": betaProductName, "quantity": 1}},
		"couponCode":   couponCode,
	})
	if exploitResp.Status == "ok" {
		var exploitOrder placeOrderOrderData
		_ = json.Unmarshal(exploitResp.Data, &exploitOrder)
		createdBetaOrder = exploitOrder.Name
		t.Fatalf("invariant violated: alice (%s, no role in %s) placed an order INSIDE %s via a forged owner query parameter: owner=%s name=%s user=%s couponName=%s - a buyer with zero membership in the target organization redeemed its coupon and consumed its inventory",
			aliceOrg, betaAdminOrg, betaAdminOrg, exploitOrder.Owner, exploitOrder.Name, exploitOrder.User, exploitOrder.CouponName)
	}
}
