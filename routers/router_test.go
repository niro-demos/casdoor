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

package routers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/session"
)

var initAPITestOnce sync.Once

func serveAPIRequest(method, target string, headers map[string]string) *httptest.ResponseRecorder {
	initAPITestOnce.Do(func() {
		web.BConfig.WebConfig.Session.SessionOn = true
		web.GlobalSessions, _ = session.NewManager("memory", session.NewManagerConfig(
			session.CfgCookieName("casdoor_session_id"),
			session.CfgSetCookie(true),
			session.CfgGcLifeTime(3600),
			session.CfgCookieLifeTime(3600),
		))
		InitAPI()
	})

	req := httptest.NewRequest(method, target, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	web.BeeApp.Handlers.ServeHTTP(recorder, req)
	return recorder
}

func TestSsoLogoutRejectsCrossSiteNavigationGet(t *testing.T) {
	recorder := serveAPIRequest(http.MethodGet, "/api/sso-logout", map[string]string{
		"Referer":        "https://attacker.invalid/landing",
		"Sec-Fetch-Site": "cross-site",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-User": "?1",
	})

	if recorder.Code == http.StatusOK && strings.Contains(recorder.Body.String(), `"status":"ok"`) {
		t.Fatalf("cross-site GET /api/sso-logout reached logout handler: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestSsoLogoutPostRouteRemainsAvailable(t *testing.T) {
	recorder := serveAPIRequest(http.MethodPost, "/api/sso-logout", nil)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"ok"`) {
		t.Fatalf("POST /api/sso-logout should remain available for application logout: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
}
