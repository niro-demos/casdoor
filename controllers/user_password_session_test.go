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

package controllers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

const (
	passwordSessionOrg         = "password-session-org"
	passwordSessionApp         = "password-session-app"
	passwordSessionUser        = "password-session-user"
	passwordSessionOldPassword = "OldPass123!"
	passwordSessionNewPassword = "NewPass456!"
)

var initPasswordSessionServerOnce sync.Once

type apiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

type accountData struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type accountResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func TestSetPasswordInvalidatesExistingAccountSessions(t *testing.T) {
	setupPasswordSessionServer(t)

	server := httptest.NewServer(web.BeeApp.Handlers)
	t.Cleanup(server.Close)

	sessionA := newTestClient(t)
	sessionB := newTestClient(t)

	requireLogin(t, sessionA, server.URL, passwordSessionOldPassword)
	requireLogin(t, sessionB, server.URL, passwordSessionOldPassword)
	requireAccount(t, sessionB, server.URL, "positive control before password change")

	changePassword(t, sessionA, server.URL)

	freshSession := newTestClient(t)
	requireLogin(t, freshSession, server.URL, passwordSessionNewPassword)
	requireAccount(t, freshSession, server.URL, "positive control after password change")

	account, raw, status := getAccount(t, sessionB, server.URL)
	if status == http.StatusOK && account.Status == "ok" && account.Data.Owner == passwordSessionOrg && account.Data.Name == passwordSessionUser {
		t.Fatalf("pre-change session remained authenticated as %s/%s after password change; response=%s", account.Data.Owner, account.Data.Name, raw)
	}
}

func setupPasswordSessionServer(t *testing.T) {
	t.Helper()

	initPasswordSessionServerOnce.Do(func() {
		dir := t.TempDir()
		dbPath := filepath.ToSlash(filepath.Join(dir, "casdoor-test.db"))
		configPath := filepath.Join(dir, "app.conf")
		config := fmt.Sprintf(`appname = casdoor
runmode = test
copyrequestbody = true
driverName = sqlite
dataSourceName = file:%s?cache=shared
dbName =
tableNamePrefix =
showSql = false
staticBaseUrl = "https://cdn.casbin.org"
defaultApplication = "app-built-in"
initDataFile = "./init_data.json"
sessionon = true
sessionprovider = memory
`, dbPath)
		if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		oldArgs := os.Args
		os.Args = append([]string{oldArgs[0]}, "-config", configPath)
		object.InitFlag()
		os.Args = oldArgs

		web.InitBeegoBeforeTest(configPath)
		web.BConfig.CopyRequestBody = true
		web.BConfig.WebConfig.Session.SessionOn = true
		object.InitAdapter()
		object.CreateTables()
		object.InitDb()

		seedPasswordSessionUser(t)
		routers.InitAPI()
		web.BeeApp.Handlers.Init()
	})
}

func seedPasswordSessionUser(t *testing.T) {
	t.Helper()

	_, err := object.AddOrganization(&object.Organization{
		Owner:           "admin",
		Name:            passwordSessionOrg,
		DisplayName:     "Password Session Test",
		PasswordType:    "bcrypt",
		PasswordOptions: []string{"AtLeast6"},
		AccountItems:    object.GetDefaultAccountItems(),
	})
	if err != nil {
		t.Fatalf("add organization: %v", err)
	}

	_, err = object.AddApplication(&object.Application{
		Owner:        "admin",
		Name:         passwordSessionApp,
		DisplayName:  "Password Session Test",
		Organization: passwordSessionOrg,
		SigninMethods: []*object.SigninMethod{
			{Name: "Password", DisplayName: "Password"},
		},
	})
	if err != nil {
		t.Fatalf("add application: %v", err)
	}

	_, err = object.AddUser(&object.User{
		Owner:             passwordSessionOrg,
		Name:              passwordSessionUser,
		Type:              "normal-user",
		Password:          passwordSessionOldPassword,
		DisplayName:       "Password Session Test User",
		SignupApplication: passwordSessionApp,
	}, "en")
	if err != nil {
		t.Fatalf("add user: %v", err)
	}
}

func newTestClient(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar}
}

func requireLogin(t *testing.T, client *http.Client, target string, password string) {
	t.Helper()

	body := map[string]string{
		"application":  passwordSessionApp,
		"organization": passwordSessionOrg,
		"username":     passwordSessionUser,
		"password":     password,
		"signinMethod": "Password",
		"type":         "login",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, target+"/api/login", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()

	parsed, raw := readAPIResponse(t, resp.Body)
	if resp.StatusCode != http.StatusOK || parsed.Status != "ok" {
		t.Fatalf("login returned HTTP %d status=%q msg=%q body=%s", resp.StatusCode, parsed.Status, parsed.Msg, raw)
	}
}

func changePassword(t *testing.T, client *http.Client, target string) {
	t.Helper()

	form := url.Values{}
	form.Set("userOwner", passwordSessionOrg)
	form.Set("userName", passwordSessionUser)
	form.Set("oldPassword", passwordSessionOldPassword)
	form.Set("newPassword", passwordSessionNewPassword)

	req, err := http.NewRequest(http.MethodPost, target+"/api/set-password", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build set-password request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("set-password request: %v", err)
	}
	defer resp.Body.Close()

	parsed, raw := readAPIResponse(t, resp.Body)
	if resp.StatusCode != http.StatusOK || parsed.Status != "ok" {
		t.Fatalf("set-password returned HTTP %d status=%q msg=%q body=%s", resp.StatusCode, parsed.Status, parsed.Msg, raw)
	}
}

func requireAccount(t *testing.T, client *http.Client, target string, action string) {
	t.Helper()

	account, raw, status := getAccount(t, client, target)
	if status != http.StatusOK || account.Status != "ok" || account.Data.Owner != passwordSessionOrg || account.Data.Name != passwordSessionUser {
		t.Fatalf("%s: expected authenticated account %s/%s, got HTTP %d body=%s", action, passwordSessionOrg, passwordSessionUser, status, raw)
	}
}

func getAccount(t *testing.T, client *http.Client, target string) (*struct {
	Status string
	Msg    string
	Data   accountData
}, string, int) {
	t.Helper()

	resp, err := client.Get(target + "/api/get-account")
	if err != nil {
		t.Fatalf("get-account request: %v", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read get-account response: %v", err)
	}

	var parsed accountResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("decode get-account response: %v: %s", err, data)
	}
	result := &struct {
		Status string
		Msg    string
		Data   accountData
	}{Status: parsed.Status, Msg: parsed.Msg}
	if parsed.Status == "ok" {
		if err := json.Unmarshal(parsed.Data, &result.Data); err != nil {
			t.Fatalf("decode get-account data: %v: %s", err, data)
		}
	}
	return result, string(data), resp.StatusCode
}

func readAPIResponse(t *testing.T, body io.Reader) (*apiResponse, string) {
	t.Helper()

	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var parsed apiResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("decode response: %v: %s", err, data)
	}
	return &parsed, string(data)
}
