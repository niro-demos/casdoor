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

// Invariant under test (TC-56B66E08): unpublished/draft products that an org
// admin has not published must not be visible to anonymous visitors or
// non-members of that organization, regardless of whether the caller passes
// pagination parameters.

var initApp sync.Once

// bootApp brings up enough of the real Casdoor server (DB + routes + authz
// policy) in-process to exercise the actual HTTP handler for GET
// /api/get-products, exactly as it runs in production. It mirrors the
// relevant subset of main.go's startup sequence.
func bootApp(t *testing.T) *httptest.Server {
	t.Helper()

	initApp.Do(func() {
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
		authz.InitApi()          // (re)loads the built-in casbin policy, including "GET /api/get-products" for "*"
		object.InitUserManager() // wires up the user/group casbin enforcer used by DeleteUser during cleanup
		routers.InitAPI()        // registers all routes, including /api/get-products and /api/login
	})

	return httptest.NewServer(web.BeeApp.Handlers)
}

type apiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type productDTO struct {
	Owner       string  `json:"owner"`
	Name        string  `json:"name"`
	DisplayName string  `json:"displayName"`
	Price       float64 `json:"price"`
	State       string  `json:"state"`
}

func newHTTPClient(withJar bool) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if withJar {
		jar, _ := cookiejar.New(nil)
		c.Jar = jar
	}
	return c
}

func doGet(t *testing.T, client *http.Client, url string) apiResponse {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out apiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
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

func parseProducts(t *testing.T, resp apiResponse) []productDTO {
	t.Helper()
	if resp.Status != "ok" {
		t.Fatalf("get-products failed: %s", resp.Msg)
	}
	var products []productDTO
	if len(resp.Data) > 0 && string(resp.Data) != "null" {
		if err := json.Unmarshal(resp.Data, &products); err != nil {
			t.Fatalf("bad products payload: %v (data=%s)", err, resp.Data)
		}
	}
	return products
}

func containsProduct(products []productDTO, name string) *productDTO {
	for i := range products {
		if products[i].Name == name {
			return &products[i]
		}
	}
	return nil
}

// productTestFixture seeds a throwaway organization, application, org-admin
// user, and one Draft + one Published product, and returns a cleanup func.
type productTestFixture struct {
	Owner         string
	AdminName     string
	AdminPass     string
	AppName       string
	DraftName     string
	PublishedName string
}

func setupProductFixture(t *testing.T) productTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner := "sec-test-org-" + suffix
	appName := "sec-test-app-" + suffix
	adminName := "org-admin"
	adminPass := "NiroTestPass123!"
	draftName := "draft-product-" + suffix
	publishedName := "published-product-" + suffix

	org := &object.Organization{
		Owner:           "admin",
		Name:            owner,
		CreatedTime:     time.Now().Format(time.RFC3339),
		DisplayName:     "Security Test Org " + suffix,
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
		DisplayName:         "Security Test App " + suffix,
		Organization:        owner,
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
	if _, err := object.AddApplication(app); err != nil {
		t.Fatalf("failed to create test application: %v", err)
	}

	admin := &object.User{
		Owner:             owner,
		Name:              adminName,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          adminPass,
		DisplayName:       "Org Admin",
		Email:             "org-admin-" + suffix + "@example.com",
		IsAdmin:           true,
		SignupApplication: appName,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(admin, "en"); err != nil {
		t.Fatalf("failed to create test org admin user: %v", err)
	}

	draft := &object.Product{
		Owner:       owner,
		Name:        draftName,
		CreatedTime: time.Now().Format(time.RFC3339),
		DisplayName: "Secret Draft Product " + suffix,
		Detail:      "unreleased internal draft",
		Currency:    "USD",
		Price:       12345,
		Quantity:    1,
		Providers:   []string{"placeholder-provider"},
		State:       "Draft",
	}
	if _, err := object.AddProduct(draft); err != nil {
		t.Fatalf("failed to create draft product: %v", err)
	}

	published := &object.Product{
		Owner:       owner,
		Name:        publishedName,
		CreatedTime: time.Now().Format(time.RFC3339),
		DisplayName: "Published Product " + suffix,
		Detail:      "generally available",
		Currency:    "USD",
		Price:       999,
		Quantity:    1,
		Providers:   []string{"placeholder-provider"},
		State:       "Published",
	}
	if _, err := object.AddProduct(published); err != nil {
		t.Fatalf("failed to create published product: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteProduct(draft)
		_, _ = object.DeleteProduct(published)
		_, _ = object.DeleteUser(admin)
		_, _ = object.DeleteApplication(app)
		_, _ = object.DeleteOrganization(org)
	})

	return productTestFixture{
		Owner:         owner,
		AdminName:     adminName,
		AdminPass:     adminPass,
		AppName:       appName,
		DraftName:     draftName,
		PublishedName: publishedName,
	}
}

// TestGetProductsHidesDraftFromAnonymousCallers is the regression test for
// TC-56B66E08. It must fail (red) on the unfixed controllers/product.go,
// where GetProducts() calls object.GetProducts(owner) unfiltered whenever
// pageSize/p are omitted, leaking Draft products to anonymous callers.
func TestGetProductsHidesDraftFromAnonymousCallers(t *testing.T) {
	server := bootApp(t)
	defer server.Close()

	fx := setupProductFixture(t)
	anon := newHTTPClient(false) // no cookies -- fully unauthenticated

	// Positive control: the paginated, state=Published-filtered path (the one
	// the storefront UI actually uses) must exclude the Draft product. This
	// proves the fixture/environment is healthy and isolates the vulnerable
	// path below.
	controlURL := fmt.Sprintf("%s/api/get-products?owner=%s&pageSize=10&p=1&field=state&value=Published", server.URL, fx.Owner)
	controlProducts := parseProducts(t, doGet(t, anon, controlURL))
	if leaked := containsProduct(controlProducts, fx.DraftName); leaked != nil {
		t.Fatalf("SETUP FAILURE: positive control itself leaked the draft product: %+v", leaked)
	}
	if containsProduct(controlProducts, fx.PublishedName) == nil {
		t.Fatalf("SETUP FAILURE: positive control did not return the published product at all")
	}

	// Vulnerable path: no pageSize/p at all. Per the invariant, an anonymous
	// caller must still not see the Draft product.
	vulnerableURL := fmt.Sprintf("%s/api/get-products?owner=%s", server.URL, fx.Owner)
	products := parseProducts(t, doGet(t, anon, vulnerableURL))

	if leaked := containsProduct(products, fx.DraftName); leaked != nil {
		t.Fatalf("invariant violated: unauthenticated caller (no cookies, no pageSize/p) retrieved a Draft product via GET /api/get-products: name=%s displayName=%q price=%v state=%s",
			leaked.Name, leaked.DisplayName, leaked.Price, leaked.State)
	}

	// The legitimate Published product must still be visible on this path --
	// the fix must not hide products that were always meant to be public.
	if containsProduct(products, fx.PublishedName) == nil {
		t.Fatalf("regression: the no-pagination path stopped returning Published products for anonymous callers")
	}
}

// TestGetProductsShowsDraftToOrgAdmin proves the fix does not break the
// legitimate use case (CouponEditPage / OrderEditPage / the admin console),
// which all call the no-pagination branch of GET /api/get-products expecting
// to see every product -- including Draft ones -- for an authenticated
// admin of the owning organization.
func TestGetProductsShowsDraftToOrgAdmin(t *testing.T) {
	server := bootApp(t)
	defer server.Close()

	fx := setupProductFixture(t)
	admin := newHTTPClient(true)

	loginResp := doPostJSON(t, admin, server.URL+"/api/login", map[string]interface{}{
		"username":     fx.AdminName,
		"password":     fx.AdminPass,
		"organization": fx.Owner,
		"application":  fx.AppName,
		"signinMethod": "Password",
		"type":         "login",
	})
	if loginResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: could not log in as the test org admin: %s", loginResp.Msg)
	}

	url := fmt.Sprintf("%s/api/get-products?owner=%s", server.URL, fx.Owner)
	products := parseProducts(t, doGet(t, admin, url))

	if containsProduct(products, fx.DraftName) == nil {
		t.Fatalf("behavior regression: the owning organization's admin no longer sees the Draft product via GET /api/get-products")
	}
	if containsProduct(products, fx.PublishedName) == nil {
		t.Fatalf("behavior regression: the owning organization's admin no longer sees the Published product via GET /api/get-products")
	}
}
