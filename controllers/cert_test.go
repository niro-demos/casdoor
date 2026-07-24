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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	_ "unsafe"
)

//go:linkname testOrmer github.com/casdoor/casdoor/object.ormer
var testOrmer *object.Ormer

const testCertPrivateKey = "-----BEGIN PRIVATE KEY-----\nredacted-test-key\n-----END PRIVATE KEY-----"

type certResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func setupCertMaskingTestStore(t *testing.T) {
	t.Helper()

	adapter, err := object.NewAdapter("sqlite", fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = adapter.Engine.Close()
		testOrmer = nil
	})

	testOrmer = adapter
	if err := testOrmer.Engine.Sync2(new(object.User), new(object.ThirdPartyLink), new(object.Cert)); err != nil {
		t.Fatal(err)
	}

	_, err = testOrmer.Engine.Insert(
		&object.User{Owner: "built-in", Name: "admin", IsAdmin: true},
		&object.User{Owner: "niro-test", Name: "org-admin", IsAdmin: true},
		&object.Cert{
			Owner:       "admin",
			Name:        "cert-built-in",
			CreatedTime: "2026-07-24T00:00:00Z",
			Scope:       "JWT",
			Type:        "x509",
			PrivateKey:  testCertPrivateKey,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func executeCertRequest(t *testing.T, currentUserId string, path string, action func(*ApiController)) []byte {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.SetData("currentUserId", currentUserId)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", controller)
	action(controller)

	if recorder.Code != http.StatusOK {
		t.Fatalf("%s returned HTTP %d: %s", path, recorder.Code, recorder.Body.String())
	}

	var response certResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode %s response: %v\n%s", path, err, recorder.Body.String())
	}
	if response.Status != "ok" {
		t.Fatalf("%s returned status=%q msg=%q", path, response.Status, response.Msg)
	}
	return response.Data
}

func assertMaskedPrivateKey(t *testing.T, endpoint string, data []byte) {
	t.Helper()

	raw := string(data)
	if strings.Contains(raw, "-----BEGIN") || strings.Contains(raw, "PRIVATE KEY-----") {
		t.Fatalf("%s leaked PEM private key: %s", endpoint, raw)
	}
	if !strings.Contains(raw, `"privateKey":"***"`) {
		t.Fatalf("%s did not mask privateKey: %s", endpoint, raw)
	}
}

func assertUnmaskedPrivateKey(t *testing.T, endpoint string, data []byte) {
	t.Helper()

	raw := string(data)
	if !strings.Contains(raw, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("%s did not return unmasked privateKey for global admin: %s", endpoint, raw)
	}
}

func TestOrgAdminCertificateReadsMaskPrivateKeys(t *testing.T) {
	setupCertMaskingTestStore(t)

	tests := []struct {
		name   string
		path   string
		action func(*ApiController)
	}{
		{
			name:   "get certs",
			path:   "/api/get-certs?owner=niro-test",
			action: (*ApiController).GetCerts,
		},
		{
			name:   "get global certs",
			path:   "/api/get-global-certs?owner=niro-test",
			action: (*ApiController).GetGlobalCerts,
		},
		{
			name:   "get cert",
			path:   "/api/get-cert?id=admin/cert-built-in",
			action: (*ApiController).GetCert,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := executeCertRequest(t, "niro-test/org-admin", tt.path, tt.action)
			assertMaskedPrivateKey(t, tt.path, data)
		})
	}

	t.Run("global admin can read private key", func(t *testing.T) {
		data := executeCertRequest(t, "built-in/admin", "/api/get-cert?id=admin/cert-built-in", (*ApiController).GetCert)
		assertUnmaskedPrivateKey(t, "/api/get-cert?id=admin/cert-built-in", data)
	})
}
