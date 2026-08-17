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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestAddTicketNormalizesInitialMessageAttribution(t *testing.T) {
	setupTicketControllerTest(t)

	_, err := object.AddOrganization(&object.Organization{Owner: "admin", Name: "built-in", HasPrivilegeConsent: true})
	if err != nil {
		t.Fatalf("AddOrganization() error = %v", err)
	}

	_, err = object.AddUser(&object.User{
		Owner:   "built-in",
		Name:    "admin",
		IsAdmin: true,
	}, "en")
	if err != nil {
		t.Fatalf("AddUser() error = %v", err)
	}

	payload := object.Ticket{
		Owner:   "built-in",
		Name:    "initial-message-forgery",
		Title:   "authorship probe",
		Content: "test",
		State:   "Open",
		Messages: []*object.TicketMessage{{
			Author:    "built-in/different-admin",
			Text:      "forged admin endorsement",
			Timestamp: "2026-08-17T00:00:00Z",
			IsAdmin:   false,
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/add-ticket", bytes.NewReader(body))
	ctx := context.NewContext()
	ctx.Reset(recorder, request)
	ctx.Input.RequestBody = body
	ctx.Input.SetData("currentUserId", "built-in/admin")

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "AddTicket", nil)
	controller.AddTicket()

	if recorder.Code != http.StatusOK {
		t.Fatalf("AddTicket() HTTP status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	ticket, err := object.GetTicket("built-in/initial-message-forgery")
	if err != nil {
		t.Fatalf("GetTicket() error = %v", err)
	}
	if ticket == nil {
		t.Fatal("GetTicket() returned nil")
	}
	if ticket.User != "built-in/admin" {
		t.Fatalf("ticket.User = %q, want %q", ticket.User, "built-in/admin")
	}
	if len(ticket.Messages) != 1 {
		t.Fatalf("len(ticket.Messages) = %d, want 1", len(ticket.Messages))
	}
	if ticket.Messages[0].Author != "built-in/admin" {
		t.Fatalf("initial message author = %q, want %q", ticket.Messages[0].Author, "built-in/admin")
	}
	if !ticket.Messages[0].IsAdmin {
		t.Fatal("initial message IsAdmin = false, want true")
	}
}

func setupTicketControllerTest(t *testing.T) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(".."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatal(err)
		}
	})

	dbPath := filepath.Join(t.TempDir(), "casdoor-ticket-test.db")
	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", dbPath)
	t.Setenv("dbName", "")
	t.Setenv("showSql", "false")

	web.BConfig.WebConfig.Session.SessionOn = true
	object.SetCreateDatabaseForTesting(false)
	object.InitAdapter()
	object.CreateTables()

	t.Cleanup(func() {
		_ = os.Remove(dbPath)
	})
}
