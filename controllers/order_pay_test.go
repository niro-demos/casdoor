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

// Invariant under test (TC-B3B9A3D9): a logged-in user from one tenant must
// not be able to create order records inside a different tenant by forging
// the `owner` query parameter on POST /api/place-order. The order must be
// scoped to the authenticated caller's own organization, not to whatever
// `owner` the client sends.

var initOrderApp sync.Once

// bootOrderApp brings up enough of the real Casdoor server (DB + routes +
// authz policy) in-process to exercise the actual HTTP handler for POST
// /api/place-order, exactly as it runs in production.
func bootOrderApp(t *testing.T) *httptest.Server {
	t.Helper()

	initOrderApp.Do(func() {
		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.BConfig.WebConfig.Session.SessionProviderConfig = ""
		web.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24 * 30
		web.BConfig.WebConfig.Session.SessionGCMaxLifetime = int64(3600 * 24 * 30)

		web.InitBeegoBeforeTest("../conf/app.conf")

		object.InitAdapter()
		object.CreateTables()
		object.InitDb()
		authz.InitApi()
		object.InitUserManager()
		routers.InitAPI()
	})

	return httptest.NewServer(web.BeeApp.Handlers)
}

type orderAPIResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type orderDTO struct {
	Owner string  `json:"owner"`
	Name  string  `json:"name"`
	User  string  `json:"user"`
	Price float64 `json:"price"`
}

func newOrderHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Timeout: 15 * time.Second, Jar: jar}
}

func orderDoPostJSON(t *testing.T, client *http.Client, url string, body interface{}) orderAPIResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out orderAPIResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

// orderTestTenant is one throwaway organization + application + admin +
// "alice" user + one Published product, used to build a pair of tenants for
// the cross-tenant forgery test.
type orderTestTenant struct {
	Owner       string
	AppName     string
	AliceName   string
	AlicePass   string
	ProductName string

	org     *object.Organization
	app     *object.Application
	alice   *object.User
	product *object.Product
}

func setupOrderTestTenant(t *testing.T, label string) orderTestTenant {
	t.Helper()

	suffix := fmt.Sprintf("%s-%d", label, time.Now().UnixNano())
	owner := "sec-order-org-" + suffix
	appName := "sec-order-app-" + suffix
	alicePass := "NiroTestPass123!"
	productName := "sec-order-product-" + suffix

	org := &object.Organization{
		Owner:           "admin",
		Name:            owner,
		CreatedTime:     time.Now().Format(time.RFC3339),
		DisplayName:     "Security Order Test Org " + suffix,
		PasswordType:    "plain",
		PasswordOptions: []string{"AtLeast6"},
		CountryCodes:    []string{"US"},
		Tags:            []string{},
		Languages:       []string{"en"},
		AccountItems:    object.GetDefaultAccountItems(),
	}
	if _, err := object.AddOrganization(org); err != nil {
		t.Fatalf("failed to create test organization: %v", err)
	}

	app := &object.Application{
		Owner:               "admin",
		Name:                appName,
		CreatedTime:         time.Now().Format(time.RFC3339),
		DisplayName:         "Security Order Test App " + suffix,
		Organization:        owner,
		Cert:                "cert-built-in",
		EnablePassword:      true,
		SigninMethods:       []*object.SigninMethod{{Name: "Password", DisplayName: "Password", Rule: "All"}},
		Providers:           []*object.ProviderItem{},
		RedirectUris:        []string{},
		Tags:                []string{},
		TokenFormat:         "JWT",
		TokenFields:         []string{},
		ExpireInHours:       168,
		FormOffset:          2,
		CookieExpireInHours: 720,
	}
	if _, err := object.AddApplication(app); err != nil {
		t.Fatalf("failed to create test application: %v", err)
	}

	// Every tenant seeds a user with the SAME local username ("alice") on
	// purpose -- this mirrors the finding's real-world scenario where a
	// forged order becomes indistinguishable from one the same-named victim
	// created herself.
	alice := &object.User{
		Owner:             owner,
		Name:              "alice",
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          alicePass,
		DisplayName:       "Alice " + suffix,
		Email:             "alice-" + suffix + "@example.com",
		IsAdmin:           false,
		SignupApplication: appName,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(alice, "en"); err != nil {
		t.Fatalf("failed to create test user alice: %v", err)
	}

	product := &object.Product{
		Owner:       owner,
		Name:        productName,
		CreatedTime: time.Now().Format(time.RFC3339),
		DisplayName: "Secret Product " + suffix,
		Detail:      "tenant-scoped product",
		Currency:    "USD",
		Price:       88.88,
		Quantity:    50,
		Providers:   []string{"placeholder-provider"},
		State:       "Published",
	}
	if _, err := object.AddProduct(product); err != nil {
		t.Fatalf("failed to create test product: %v", err)
	}

	tenant := orderTestTenant{
		Owner:       owner,
		AppName:     appName,
		AliceName:   "alice",
		AlicePass:   alicePass,
		ProductName: productName,
		org:         org,
		app:         app,
		alice:       alice,
		product:     product,
	}

	t.Cleanup(func() {
		orders, _ := object.GetOrders(owner)
		for _, o := range orders {
			_, _ = object.DeleteOrder(o)
		}
		_, _ = object.DeleteProduct(product)
		_, _ = object.DeleteUser(alice)
		_, _ = object.DeleteApplication(app)
		_, _ = object.DeleteOrganization(org)
	})

	return tenant
}

func orderLogin(t *testing.T, client *http.Client, serverURL string, tenant orderTestTenant) {
	t.Helper()
	resp := orderDoPostJSON(t, client, serverURL+"/api/login", map[string]interface{}{
		"username":     tenant.AliceName,
		"password":     tenant.AlicePass,
		"organization": tenant.Owner,
		"application":  tenant.AppName,
		"signinMethod": "Password",
		"type":         "login",
	})
	if resp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: could not log in as %s/%s: %s", tenant.Owner, tenant.AliceName, resp.Msg)
	}
}

// TestPlaceOrderRejectsCrossTenantOwner is the regression test for
// TC-B3B9A3D9. It must fail (red) on the unfixed controllers/order_pay.go,
// where PlaceOrder() reads `owner` straight from the client-controlled query
// string and never checks it against the authenticated caller's own
// organization.
func TestPlaceOrderRejectsCrossTenantOwner(t *testing.T) {
	server := bootOrderApp(t)
	defer server.Close()

	tenantA := setupOrderTestTenant(t, "alpha")
	tenantB := setupOrderTestTenant(t, "beta")

	aliceA := newOrderHTTPClient()
	orderLogin(t, aliceA, server.URL, tenantA)

	// Positive control: alice (tenant A) places an order under her OWN
	// tenant, for a product that actually belongs to tenant A. This must
	// succeed, proving the order pipeline itself is healthy and isolating
	// the negative case below as the specific invariant violation.
	controlURL := fmt.Sprintf("%s/api/place-order?owner=%s", server.URL, tenantA.Owner)
	controlResp := orderDoPostJSON(t, aliceA, controlURL, map[string]interface{}{
		"productInfos": []map[string]interface{}{
			{"name": tenantA.ProductName, "quantity": 1, "owner": tenantA.Owner},
		},
	})
	if controlResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: alice could not place a legitimate own-tenant order: %s", controlResp.Msg)
	}
	var controlOrder orderDTO
	if err := json.Unmarshal(controlResp.Data, &controlOrder); err != nil {
		t.Fatalf("SETUP FAILURE: could not parse own-tenant order response: %v (data=%s)", err, controlResp.Data)
	}
	if controlOrder.Owner != tenantA.Owner {
		t.Fatalf("SETUP FAILURE: own-tenant order was not scoped to tenant A: %+v", controlOrder)
	}

	// The actual vulnerability: alice, still authenticated only as
	// tenantA/alice, forges the `owner` query parameter to point at tenant
	// B and targets tenant B's product, which she has no relationship to.
	forgedURL := fmt.Sprintf("%s/api/place-order?owner=%s", server.URL, tenantB.Owner)
	forgedResp := orderDoPostJSON(t, aliceA, forgedURL, map[string]interface{}{
		"productInfos": []map[string]interface{}{
			{"name": tenantB.ProductName, "quantity": 1, "owner": tenantB.Owner},
		},
	})

	if forgedResp.Status == "ok" {
		var forged orderDTO
		_ = json.Unmarshal(forgedResp.Data, &forged)
		t.Fatalf("invariant violated: tenant-A caller (owner=%s, session %s/%s) created an order scoped to tenant B: owner=%s name=%s user=%s price=%v",
			tenantA.Owner, tenantA.Owner, tenantA.AliceName, forged.Owner, forged.Name, forged.User, forged.Price)
	}

	// Confirm no forged order landed in tenant B's order table at all --
	// this is what would otherwise surface in the real tenant-B alice's own
	// order history.
	tenantBOrders, err := object.GetUserOrders(tenantB.Owner, tenantB.AliceName)
	if err != nil {
		t.Fatalf("could not check tenant B orders: %v", err)
	}
	if len(tenantBOrders) != 0 {
		t.Fatalf("invariant violated: %d order(s) exist in tenant B's own order history that tenant-B alice never created: %+v", len(tenantBOrders), tenantBOrders)
	}
}
