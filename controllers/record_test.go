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
	"github.com/casdoor/casdoor/util"
)

// Invariant under test (TC-AADF16A2): an organization administrator must only
// be able to view audit/login records that belong to their own organization
// via GET /api/get-records; they must not be able to read every
// organization's audit records platform-wide by omitting the pageSize/p
// pagination parameters.

var initRecordTestApp sync.Once

// bootRecordTestApp brings up enough of the real Casdoor server (DB + routes
// + authz policy) in-process to exercise the actual HTTP handler for GET
// /api/get-records, exactly as it runs in production. It mirrors the
// relevant subset of main.go's startup sequence.
func bootRecordTestApp(t *testing.T) *httptest.Server {
	t.Helper()

	initRecordTestApp.Do(func() {
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

type recordApiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type recordDTO struct {
	Id           int    `json:"id"`
	Organization string `json:"organization"`
	RequestUri   string `json:"requestUri"`
}

func newRecordTestHTTPClient(withJar bool) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if withJar {
		jar, _ := cookiejar.New(nil)
		c.Jar = jar
	}
	return c
}

func recordTestGet(t *testing.T, client *http.Client, url string) recordApiResponse {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out recordApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

func recordTestPostJSON(t *testing.T, client *http.Client, url string, body map[string]interface{}) recordApiResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out recordApiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bad JSON from %s: %v (body=%s)", url, err, raw)
	}
	return out
}

func parseRecords(t *testing.T, resp recordApiResponse) []recordDTO {
	t.Helper()
	if resp.Status != "ok" {
		t.Fatalf("get-records failed: %s", resp.Msg)
	}
	var records []recordDTO
	if len(resp.Data) > 0 && string(resp.Data) != "null" {
		if err := json.Unmarshal(resp.Data, &records); err != nil {
			t.Fatalf("bad records payload: %v (data=%s)", err, resp.Data)
		}
	}
	return records
}

func containsRecordWithRequestUri(records []recordDTO, requestUri string) *recordDTO {
	for i := range records {
		if records[i].RequestUri == requestUri {
			return &records[i]
		}
	}
	return nil
}

// recordTestFixture seeds a throwaway organization, application, and org-admin
// user (the "alpha" tenant), plus one Record row directly owned by that
// tenant and one Record row belonging to a different ("beta") tenant. Only
// alpha gets a real Organization/Application/User (all we need to log in as
// its admin); beta is only a distinct organization name on the Record rows,
// since object.Record has no foreign-key relationship to Organization.
type recordTestFixture struct {
	AlphaOrg        string
	AdminName       string
	AdminPass       string
	AppName         string
	AlphaRequestUri string
	BetaRequestUri  string
}

func setupRecordFixture(t *testing.T) recordTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	alphaOrg := "sec-rec-alpha-" + suffix
	betaOrg := "sec-rec-beta-" + suffix
	appName := "sec-rec-app-" + suffix
	adminName := "org-admin"
	adminPass := "NiroTestPass123!"
	alphaRequestUri := "/marker-alpha-" + suffix
	betaRequestUri := "/marker-beta-" + suffix

	org := &object.Organization{
		Owner:           "admin",
		Name:            alphaOrg,
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
		Organization:        alphaOrg,
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

	admin := &object.User{
		Owner:             alphaOrg,
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

	// A record that legitimately belongs to alpha's own tenant.
	alphaRecord := &object.Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: alphaOrg,
		ClientIp:     "127.0.0.1",
		Method:       "POST",
		RequestUri:   alphaRequestUri,
		Action:       "login",
		Language:     "en",
		StatusCode:   200,
	}
	if !object.AddRecord(alphaRecord) {
		t.Fatalf("failed to seed alpha-org record")
	}

	// A record belonging to a different tenant that alpha's admin must never see.
	betaRecord := &object.Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: betaOrg,
		ClientIp:     "10.0.0.9",
		Method:       "POST",
		RequestUri:   betaRequestUri,
		Action:       "login",
		Language:     "en",
		StatusCode:   200,
	}
	if !object.AddRecord(betaRecord) {
		t.Fatalf("failed to seed beta-org record")
	}

	t.Cleanup(func() {
		_, _ = object.DeleteUser(admin)
		_, _ = object.DeleteApplication(app)
		_, _ = object.DeleteOrganization(org)
		// object.Record rows have no exported delete API; the throwaway,
		// timestamp-suffixed organization names keep leftover rows from
		// colliding with subsequent runs.
	})

	return recordTestFixture{
		AlphaOrg:        alphaOrg,
		AdminName:       adminName,
		AdminPass:       adminPass,
		AppName:         appName,
		AlphaRequestUri: alphaRequestUri,
		BetaRequestUri:  betaRequestUri,
	}
}

func loginAsRecordFixtureAdmin(t *testing.T, server *httptest.Server, fx recordTestFixture) *http.Client {
	t.Helper()
	admin := newRecordTestHTTPClient(true)

	loginResp := recordTestPostJSON(t, admin, server.URL+"/api/login", map[string]interface{}{
		"username":     fx.AdminName,
		"password":     fx.AdminPass,
		"organization": fx.AlphaOrg,
		"application":  fx.AppName,
		"signinMethod": "Password",
		"type":         "login",
	})
	if loginResp.Status != "ok" {
		t.Fatalf("SETUP FAILURE: could not log in as the test org admin: %s", loginResp.Msg)
	}
	return admin
}

// TestGetRecordsScopesUnpaginatedPathToCallerOrganization is the regression
// test for TC-AADF16A2. It must fail (red) on the unfixed
// controllers/record.go, where GetRecords() calls the unfiltered
// object.GetRecords() whenever pageSize/p are omitted, leaking every
// organization's audit records to a non-global org admin.
func TestGetRecordsScopesUnpaginatedPathToCallerOrganization(t *testing.T) {
	server := bootRecordTestApp(t)
	defer server.Close()

	fx := setupRecordFixture(t)
	admin := loginAsRecordFixtureAdmin(t, server, fx)

	// Positive control: the paginated path, scoped with the same field/value
	// filter used to locate our seeded markers, must return alpha's own
	// record and must NOT return beta's -- proving the org-scoping logic
	// exists and the environment/fixture is healthy.
	controlURL := fmt.Sprintf("%s/api/get-records?pageSize=10&p=1&field=requestUri&value=marker-", server.URL)
	controlRecords := parseRecords(t, recordTestGet(t, admin, controlURL))
	if leaked := containsRecordWithRequestUri(controlRecords, fx.BetaRequestUri); leaked != nil {
		t.Fatalf("SETUP FAILURE: positive control itself leaked the other tenant's record: %+v", leaked)
	}
	if containsRecordWithRequestUri(controlRecords, fx.AlphaRequestUri) == nil {
		t.Fatalf("SETUP FAILURE: positive control did not return the caller's own record at all")
	}

	// Vulnerable path: no pageSize/p at all. Per the invariant, alpha's org
	// admin must still not see beta's record.
	vulnerableURL := server.URL + "/api/get-records"
	records := parseRecords(t, recordTestGet(t, admin, vulnerableURL))

	if leaked := containsRecordWithRequestUri(records, fx.BetaRequestUri); leaked != nil {
		t.Fatalf("invariant violated: org admin (organization=%s) retrieved another organization's record via GET /api/get-records (no pagination params): id=%d organization=%s requestUri=%s",
			fx.AlphaOrg, leaked.Id, leaked.Organization, leaked.RequestUri)
	}

	// The caller's own record must still be visible on this path -- the fix
	// must not hide records that were always meant to be visible to this admin.
	if containsRecordWithRequestUri(records, fx.AlphaRequestUri) == nil {
		t.Fatalf("regression: the no-pagination path stopped returning the caller's own organization's records")
	}
}
