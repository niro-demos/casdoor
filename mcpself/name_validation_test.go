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

// Regression test for the MCP write-tool name-validation bypass.
//
// Invariant: objects created or renamed through the MCP tool-call endpoint
// (add_application / update_application / add_user / update_user) must be
// subject to the SAME forbidden-character name validation as the REST
// add-/update- endpoints. A name containing any of `/?:#&%=+;` must be rejected
// on BOTH transports.
//
// The reject path returns before any object.Add*/Update* persistence call, so
// these tests exercise the guard without a database: on the unfixed code the
// handler falls through to persistence (and the test fails to observe the
// forbidden-characters error); with the fix it is rejected up front.

package mcpself

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// newRecordingController wires a McpController to an httptest recorder so that
// SendToolResult / SendToolErrorResult (which call ServeJSON) can be captured.
func newRecordingController(t *testing.T) (*McpController, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader("{}"))
	rec := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)

	c := &McpController{}
	c.Init(ctx, "McpController", "HandleMcp", c)
	c.EnableRender = false
	return c, rec
}

// decodeToolText extracts the tool result text and IsError flag from a recorded
// MCP JSON-RPC response.
func decodeToolText(t *testing.T, rec *httptest.ResponseRecorder) (string, bool) {
	t.Helper()
	var resp struct {
		Result McpCallToolResult `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not decode MCP response %q: %v", rec.Body.String(), err)
	}
	if len(resp.Result.Content) == 0 {
		t.Fatalf("MCP response had no content: %q", rec.Body.String())
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

// forbiddenName is the exact shape from the finding: metacharacters that would
// orphan the record from the owner/name composite-ID lookup.
const forbiddenName = "bad/name?x=1"

func assertRejected(t *testing.T, text string, isErr bool) {
	t.Helper()
	if !isErr || !strings.Contains(text, "forbidden characters") {
		t.Fatalf("MCP handler did NOT reject the forbidden name: isError=%v text=%q; "+
			"want a \"forbidden characters\" error (invariant: MCP must validate names like REST does)", isErr, text)
	}
}

// runHandlerExpectReject invokes an MCP handler that must reject the forbidden
// name up front — before touching persistence. The forbidden-character guard is
// the FIRST statement in each fixed handler, so on the fixed code the handler
// returns a "forbidden characters" error and never reaches the ORM. On the
// unfixed code the name is not validated and the handler falls through to the
// database layer (which, with no ORM session in a unit test, panics) — either
// way the name was not rejected, which is the invariant violation this test
// catches.
func runHandlerExpectReject(t *testing.T, invoke func(c *McpController)) {
	t.Helper()
	c, rec := newRecordingController(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MCP handler reached persistence WITHOUT validating the name "+
				"(panicked in the ORM layer: %v); invariant violated — the forbidden name "+
				"was never rejected before the write path", r)
		}
		text, isErr := decodeToolText(t, rec)
		assertRejected(t, text, isErr)
	}()
	invoke(c)
}

func TestMcpAddApplicationRejectsForbiddenName(t *testing.T) {
	runHandlerExpectReject(t, func(c *McpController) {
		c.handleAddApplicationTool(1, AddApplicationArgs{
			Application: object.Application{Owner: "admin", Name: forbiddenName, Organization: "org-alpha"},
		})
	})
}

func TestMcpUpdateApplicationRejectsForbiddenName(t *testing.T) {
	runHandlerExpectReject(t, func(c *McpController) {
		c.handleUpdateApplicationTool(1, UpdateApplicationArgs{
			Id:          "admin/app-alpha",
			Application: object.Application{Owner: "admin", Name: forbiddenName, Organization: "org-alpha"},
		})
	})
}

func TestMcpAddUserRejectsForbiddenName(t *testing.T) {
	runHandlerExpectReject(t, func(c *McpController) {
		c.handleAddUserTool(1, AddUserArgs{
			User: object.User{Owner: "org-alpha", Name: forbiddenName},
		})
	})
}

func TestMcpUpdateUserRejectsForbiddenName(t *testing.T) {
	runHandlerExpectReject(t, func(c *McpController) {
		c.handleUpdateUserTool(1, UpdateUserArgs{
			Id:   "org-alpha/alice",
			User: object.User{Owner: "org-alpha", Name: forbiddenName},
		})
	})
}
