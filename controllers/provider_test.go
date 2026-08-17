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

// Invariant under test (TC-CB4799B0): an administrator of one tenant
// organization must not be able to read the unmasked (withSecret=1)
// clientSecret of a provider that belongs to a different organization.

var initProviderApp sync.Once

// bootProviderApp brings up enough of the real Casdoor server (DB + routes +
// authz policy) in-process to exercise the actual HTTP handler for GET
// /api/get-provider, exactly as it runs in production.
func bootProviderApp(t *testing.T) *httptest.Server {
	t.Helper()

	initProviderApp.Do(func() {
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

type providerApiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type providerDTO struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

func newProviderHTTPClient(withJar bool) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if withJar {
		jar, _ := cookiejar.New(nil)
		c.Jar = jar
	}
	return c
}

func providerGet(t *testing.T, client *http.Client, url string) providerApiResponse {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out providerApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

func providerPostJSON(t *testing.T, client *http.Client, url string, body map[string]interface{}) providerApiResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out providerApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

// providerTestFixture seeds two throwaway tenant organizations (owner and
// other), each with an application and an admin user, plus one provider
// owned by the "owner" organization holding a known plaintext client secret.
type providerTestFixture struct {
	Owner        string
	OwnerAdmin   string
	OwnerPass    string
	OwnerApp     string
	Other        string
	OtherAdmin   string
	OtherPass    string
	OtherApp     string
	ProviderName string
	ClientSecret string
}

func setupProviderFixture(t *testing.T) providerTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner := "sec-test-org-owner-" + suffix
	other := "sec-test-org-other-" + suffix
	ownerAppName := "sec-test-app-owner-" + suffix
	otherAppName := "sec-test-app-other-" + suffix
	ownerAdminName := "org-admin"
	otherAdminName := "org-admin"
	adminPass := "NiroTestPass123!"
	providerName := "sec-test-provider-" + suffix
	clientSecret := "NIRO-SUPER-SECRET-" + suffix

	makeOrg := func(name string) *object.Organization {
		return &object.Organization{
			Owner:           "admin",
			Name:            name,
			CreatedTime:     time.Now().Format(time.RFC3339),
			DisplayName:     "Security Test Org " + name,
			PasswordType:    "plain",
			PasswordOptions: []string{"AtLeast6"},
			CountryCodes:    []string{"US"},
			Tags:            []string{},
			Languages:       []string{"en"},
			AccountItems:    object.GetDefaultAccountItems(),
		}
	}
	ownerOrg := makeOrg(owner)
	otherOrg := makeOrg(other)
	if _, err := object.AddOrganization(ownerOrg); err != nil {
		t.Fatalf("failed to create owner test organization: %v", err)
	}
	if _, err := object.AddOrganization(otherOrg); err != nil {
		t.Fatalf("failed to create other test organization: %v", err)
	}

	makeApp := func(appName, org string) *object.Application {
		return &object.Application{
			Owner:               "admin",
			Name:                appName,
			CreatedTime:         time.Now().Format(time.RFC3339),
			DisplayName:         "Security Test App " + appName,
			Organization:        org,
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
	}
	ownerApp := makeApp(ownerAppName, owner)
	otherApp := makeApp(otherAppName, other)
	if _, err := object.AddApplication(ownerApp); err != nil {
		t.Fatalf("failed to create owner test application: %v", err)
	}
	if _, err := object.AddApplication(otherApp); err != nil {
		t.Fatalf("failed to create other test application: %v", err)
	}

	makeAdmin := func(org, appName, name string) *object.User {
		return &object.User{
			Owner:             org,
			Name:              name,
			CreatedTime:       time.Now().Format(time.RFC3339),
			Type:              "normal-user",
			Password:          adminPass,
			DisplayName:       "Org Admin",
			Email:             "org-admin-" + org + "@example.com",
			IsAdmin:           true,
			SignupApplication: appName,
			CreatedIp:         "127.0.0.1",
		}
	}
	ownerAdmin := makeAdmin(owner, ownerAppName, ownerAdminName)
	otherAdmin := makeAdmin(other, otherAppName, otherAdminName)
	if _, err := object.AddUser(ownerAdmin, "en"); err != nil {
		t.Fatalf("failed to create owner org admin user: %v", err)
	}
	if _, err := object.AddUser(otherAdmin, "en"); err != nil {
		t.Fatalf("failed to create other org admin user: %v", err)
	}

	provider := &object.Provider{
		Owner:        owner,
		Name:         providerName,
		CreatedTime:  time.Now().Format(time.RFC3339),
		DisplayName:  "Security Test Provider " + suffix,
		Category:     "Email",
		Type:         "Default",
		ClientId:     "sec-test-client-id",
		ClientSecret: clientSecret,
	}
	if _, err := object.AddProvider(provider); err != nil {
		t.Fatalf("failed to create test provider: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteProvider(provider)
		_, _ = object.DeleteUser(ownerAdmin)
		_, _ = object.DeleteUser(otherAdmin)
		_, _ = object.DeleteApplication(ownerApp)
		_, _ = object.DeleteApplication(otherApp)
		_, _ = object.DeleteOrganization(ownerOrg)
		_, _ = object.DeleteOrganization(otherOrg)
	})

	return providerTestFixture{
		Owner:        owner,
		OwnerAdmin:   ownerAdminName,
		OwnerPass:    adminPass,
		OwnerApp:     ownerAppName,
		Other:        other,
		OtherAdmin:   otherAdminName,
		OtherPass:    adminPass,
		OtherApp:     otherAppName,
		ProviderName: providerName,
		ClientSecret: clientSecret,
	}
}

func providerLogin(t *testing.T, server *httptest.Server, client *http.Client, username, password, organization, application string) {
	t.Helper()
	resp := providerPostJSON(t, client, server.URL+"/api/login", map[string]interface{}{
		"username":     username,
		"password":     password,
		"organization": organization,
		"application":  application,
		"signinMethod": "Password",
		"type":         "login",
	})
	if resp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: could not log in as %s/%s: %s", organization, username, resp.Msg)
	}
}

// TestGetProviderCrossTenantSecretDenied is the regression test for
// TC-CB4799B0. It must fail (red) on the unfixed controllers/provider.go,
// where GetProvider() fetches purely by caller-supplied id and never checks
// that the caller's organization owns the requested provider before
// unmasking (withSecret=1) its plaintext clientSecret.
func TestGetProviderCrossTenantSecretDenied(t *testing.T) {
	server := bootProviderApp(t)
	defer server.Close()

	fx := setupProviderFixture(t)
	providerID := fx.Owner + "/" + fx.ProviderName

	// Positive control: the legitimate owner (the provider's own
	// organization admin) can still read its own provider's plaintext
	// secret with withSecret=1. Proves the feature and fixture are healthy.
	ownerClient := newProviderHTTPClient(true)
	providerLogin(t, server, ownerClient, fx.OwnerAdmin, fx.OwnerPass, fx.Owner, fx.OwnerApp)

	ctrlResp := providerGet(t, ownerClient, fmt.Sprintf("%s/api/get-provider?id=%s&withSecret=1", server.URL, providerID))
	var ctrlData providerDTO
	_ = json.Unmarshal(ctrlResp.Data, &ctrlData)
	if ctrlResp.Status != "ok" || ctrlData.ClientSecret != fx.ClientSecret {
		t.Fatalf("SETUP FAILURE: expected legitimate owner to read its own plaintext secret, got status=%s data=%s", ctrlResp.Status, ctrlResp.Data)
	}

	// Exploit / vulnerable path: a different tenant's admin (fx.Other)
	// requests the fx.Owner-owned provider by id with withSecret=1.
	otherClient := newProviderHTTPClient(true)
	providerLogin(t, server, otherClient, fx.OtherAdmin, fx.OtherPass, fx.Other, fx.OtherApp)

	exploitResp := providerGet(t, otherClient, fmt.Sprintf("%s/api/get-provider?id=%s&withSecret=1", server.URL, providerID))
	var exploitData providerDTO
	_ = json.Unmarshal(exploitResp.Data, &exploitData)

	if exploitResp.Status == "ok" && exploitData.ClientSecret == fx.ClientSecret {
		t.Fatalf("invariant violated: cross-tenant admin (%s/%s) read the plaintext clientSecret of a %s-owned provider it does not administer: %+v",
			fx.Other, fx.OtherAdmin, fx.Owner, exploitData)
	}
	if exploitResp.Status != "error" {
		t.Fatalf("unexpected response shape for cross-tenant withSecret=1 request: status=%s data=%s", exploitResp.Status, exploitResp.Data)
	}
}

// TestGetProviderMaskedReadStillPublic proves the fix does not break the
// existing, intentionally open masked-read path (no withSecret param), which
// the sign-in UI (e.g. QR-code/Telegram login) relies on to fetch
// non-secret provider config across organizations, including anonymously.
func TestGetProviderMaskedReadStillPublic(t *testing.T) {
	server := bootProviderApp(t)
	defer server.Close()

	fx := setupProviderFixture(t)
	providerID := fx.Owner + "/" + fx.ProviderName

	anon := newProviderHTTPClient(false) // no cookies -- fully unauthenticated
	resp := providerGet(t, anon, fmt.Sprintf("%s/api/get-provider?id=%s", server.URL, providerID))

	var data providerDTO
	_ = json.Unmarshal(resp.Data, &data)
	if resp.Status != "ok" || data.Name != fx.ProviderName {
		t.Fatalf("behavior regression: anonymous masked read of a provider by id stopped working: status=%s data=%s", resp.Status, resp.Data)
	}
	if data.ClientSecret == fx.ClientSecret {
		t.Fatalf("masked read leaked the plaintext clientSecret without withSecret=1: %+v", data)
	}
}
