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
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

// Invariant under test (TC-6E15E611): the CAS proxy-ticket callback
// (serviceValidate's pgtUrl parameter) must not let an authenticated caller
// force the Casdoor server to dial an arbitrary, attacker-chosen internal
// host:port, and must not echo the raw internal connection-error text back
// to the caller.

var initCasApp sync.Once

// bootCasApp brings up enough of the real Casdoor server (DB + routes +
// authz policy) in-process to exercise the actual HTTP handlers for
// /api/login and /cas/.../serviceValidate, exactly as they run in
// production. It mirrors the relevant subset of main.go's startup sequence
// (see controllers/product_test.go's bootApp for the sibling instance of
// this pattern).
func bootCasApp(t *testing.T) *httptest.Server {
	t.Helper()

	initCasApp.Do(func() {
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

type casLoginResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Data   string `json:"data"`
}

type casFailure struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

type casServiceResponse struct {
	Failure *casFailure `json:"Failure"`
	Success *struct {
		User string `json:"User"`
	} `json:"Success"`
}

// casTestFixture seeds a throwaway organization, CAS-enabled application,
// and standard user, mirroring the STANDARD_ALICE / app-niro-alpha actors
// the PoC used.
type casTestFixture struct {
	Organization string
	Application  string
	Username     string
	Password     string
	Service      string
}

func setupCasFixture(t *testing.T) casTestFixture {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgName := "cas-sec-test-org-" + suffix
	appName := "cas-sec-test-app-" + suffix
	userName := "alice"
	password := "NiroTestPass123!"
	service := "http://localhost:19001/callback"

	org := &object.Organization{
		Owner:           "admin",
		Name:            orgName,
		CreatedTime:     time.Now().Format(time.RFC3339),
		DisplayName:     "CAS Security Test Org " + suffix,
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
		DisplayName:         "CAS Security Test App " + suffix,
		Organization:        orgName,
		Cert:                "cert-built-in",
		EnablePassword:      true,
		SigninMethods:       []*object.SigninMethod{{Name: "Password", DisplayName: "Password", Rule: "All"}},
		Providers:           []*object.ProviderItem{},
		RedirectUris:        []string{service},
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

	user := &object.User{
		Owner:             orgName,
		Name:              userName,
		CreatedTime:       time.Now().Format(time.RFC3339),
		Type:              "normal-user",
		Password:          password,
		DisplayName:       "Alice",
		Email:             "alice-" + suffix + "@example.com",
		SignupApplication: appName,
		CreatedIp:         "127.0.0.1",
	}
	if _, err := object.AddUser(user, "en"); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	t.Cleanup(func() {
		_, _ = object.DeleteUser(user)
		_, _ = object.DeleteApplication(app)
		_, _ = object.DeleteOrganization(org)
	})

	return casTestFixture{
		Organization: orgName,
		Application:  appName,
		Username:     userName,
		Password:     password,
		Service:      service,
	}
}

// getCasServiceTicket logs the fixture user in via the CAS login flow and
// returns a fresh, unused CAS service ticket (mirroring the PoC's
// getFreshTicket). Tickets are single-use (the server LoadAndDeletes them
// on the first validate call), so callers need one per serviceValidate
// probe.
func getCasServiceTicket(t *testing.T, serverURL string, fx casTestFixture) string {
	t.Helper()

	body := map[string]string{
		"application":  fx.Application,
		"organization": fx.Organization,
		"username":     fx.Username,
		"password":     fx.Password,
		"signinMethod": "Password",
		"type":         "cas",
	}
	b, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/api/login?service=%s", serverURL, fx.Service)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("login read failed: %v", err)
	}
	var lr casLoginResponse
	if err := json.Unmarshal(data, &lr); err != nil {
		t.Fatalf("login unmarshal failed: %v (body=%s)", err, data)
	}
	if lr.Status != "ok" || lr.Data == "" {
		t.Fatalf("login did not return a ticket: %s", data)
	}
	return lr.Data
}

func callServiceValidate(t *testing.T, serverURL string, fx casTestFixture, ticket, pgtUrl string) (*casServiceResponse, string) {
	t.Helper()

	url := fmt.Sprintf("%s/cas/%s/%s/serviceValidate?service=%s&ticket=%s&pgtUrl=%s&format=json",
		serverURL, fx.Organization, fx.Application, fx.Service, ticket, pgtUrl)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("serviceValidate request failed: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("serviceValidate read failed: %v", err)
	}
	var sr casServiceResponse
	if err := json.Unmarshal(data, &sr); err != nil {
		t.Fatalf("serviceValidate unmarshal failed: %v (body=%s)", err, data)
	}
	return &sr, string(data)
}

// TestCasServiceValidateRejectsPrivatePgtUrlHost is the regression test for
// TC-6E15E611. It must fail (red) on the unfixed controllers/cas.go, where
// CasP3ProxyValidate only checks pgtUrl's scheme before dialing it with
// http.DefaultClient.Do -- letting a caller force the server to connect to
// an arbitrary loopback/internal host and leaking the raw dial error back
// in the response.
func TestCasServiceValidateRejectsPrivatePgtUrlHost(t *testing.T) {
	server := bootCasApp(t)
	defer server.Close()

	fx := setupCasFixture(t)

	// Malicious case: pgtUrl points at an arbitrary loopback port, unrelated
	// to the application's registered redirect URI.
	ticket := getCasServiceTicket(t, server.URL, fx)
	pgtUrl := "https://127.0.0.1:65533/ssrf-probe"
	resp, raw := callServiceValidate(t, server.URL, fx, ticket, pgtUrl)

	if resp.Failure == nil {
		t.Fatalf("invariant violated: serviceValidate with a private pgtUrl host did not fail at all: %s", raw)
	}

	// The invariant has two parts: (1) the server must not have dialed the
	// attacker-chosen host at all, and (2) even on failure it must not leak
	// the raw internal connection-error text (which lets a caller
	// distinguish reachable from unreachable internal targets).
	if strings.Contains(resp.Failure.Message, "dial tcp") {
		t.Fatalf("invariant violated: server dialed the attacker-chosen pgtUrl host and leaked the raw connect error: %s", raw)
	}
	if strings.Contains(resp.Failure.Message, "65533") {
		t.Fatalf("invariant violated: response echoed the attacker-chosen port back to the caller: %s", raw)
	}

	// Second distinct port, to rule out a coincidental result (mirrors the
	// PoC's two-probe reproduction).
	ticket2 := getCasServiceTicket(t, server.URL, fx)
	pgtUrl2 := "https://127.0.0.1:65534/ssrf-probe-2"
	resp2, raw2 := callServiceValidate(t, server.URL, fx, ticket2, pgtUrl2)
	if resp2.Failure == nil {
		t.Fatalf("invariant violated: second private pgtUrl probe did not fail: %s", raw2)
	}
	if strings.Contains(resp2.Failure.Message, "dial tcp") || strings.Contains(resp2.Failure.Message, "65534") {
		t.Fatalf("invariant violated: server dialed/leaked the attacker-chosen host for the second probe: %s", raw2)
	}
}

// TestCasServiceValidateControlBadScheme is the positive control from the
// PoC: a non-https pgtUrl must still be rejected generically before any
// dial is attempted. This proves the endpoint and test harness are healthy
// independent of the fix, isolating the failure above to the missing host
// check.
func TestCasServiceValidateControlBadScheme(t *testing.T) {
	server := bootCasApp(t)
	defer server.Close()

	fx := setupCasFixture(t)
	ticket := getCasServiceTicket(t, server.URL, fx)

	pgtUrl := "http://127.0.0.1:65535/ssrf-probe-control"
	resp, raw := callServiceValidate(t, server.URL, fx, ticket, pgtUrl)

	if resp.Failure == nil {
		t.Fatalf("SETUP FAILURE: non-https pgtUrl was not rejected: %s", raw)
	}
	if !strings.Contains(resp.Failure.Message, "not https") {
		t.Fatalf("SETUP FAILURE: non-https pgtUrl rejected with unexpected message: %s", raw)
	}
	if strings.Contains(resp.Failure.Message, "dial tcp") {
		t.Fatalf("SETUP FAILURE: non-https pgtUrl should be rejected before any dial: %s", raw)
	}
}

// TestCasServiceValidateWithoutPgtUrlStillSucceeds proves the fix does not
// break the ordinary (non-proxy) CAS validate flow, which is the common
// case: a serviceValidate call with no pgtUrl at all must still succeed.
func TestCasServiceValidateWithoutPgtUrlStillSucceeds(t *testing.T) {
	server := bootCasApp(t)
	defer server.Close()

	fx := setupCasFixture(t)
	ticket := getCasServiceTicket(t, server.URL, fx)

	url := fmt.Sprintf("%s/cas/%s/%s/serviceValidate?service=%s&ticket=%s&format=json",
		server.URL, fx.Organization, fx.Application, fx.Service, ticket)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("serviceValidate request failed: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var sr casServiceResponse
	if err := json.Unmarshal(data, &sr); err != nil {
		t.Fatalf("serviceValidate unmarshal failed: %v (body=%s)", err, data)
	}

	if sr.Failure != nil {
		t.Fatalf("behavior regression: plain serviceValidate (no pgtUrl) started failing: %s", data)
	}
	if sr.Success == nil || sr.Success.User != fx.Username {
		t.Fatalf("behavior regression: plain serviceValidate did not return the authenticated user: %s", data)
	}
}
