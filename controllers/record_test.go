package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	_ "unsafe"

	beegoctx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

//go:linkname testOrmer github.com/casdoor/casdoor/object.ormer
var testOrmer *object.Ormer

func TestGetRecordsWithoutPageStillAppliesTenantScope(t *testing.T) {
	adapter, err := object.NewAdapter("sqlite3", ":memory:", "")
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Engine.Close()

	testOrmer = adapter
	if err := adapter.Engine.Sync2(new(object.User), new(object.ThirdPartyLink), new(object.Record)); err != nil {
		t.Fatal(err)
	}

	_, err = adapter.Engine.Insert(
		&object.User{Owner: "niro-test", Name: "org-admin", IsAdmin: true},
		&object.Record{Organization: "niro-test", Owner: "niro-test", User: "org-admin", RequestUri: "/api/login"},
		&object.Record{Organization: "built-in", Owner: "built-in", User: "admin", RequestUri: "/api/login"},
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/get-records?pageSize=3", nil)
	recorder := httptest.NewRecorder()
	ctx := beegoctx.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.SetData("currentUserId", "niro-test/org-admin")

	controller := &ApiController{}
	controller.Ctx = ctx
	controller.Data = map[interface{}]interface{}{}
	controller.GetRecords()

	var response struct {
		Status string          `json:"status"`
		Data   []object.Record `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	if response.Status != "ok" {
		t.Fatalf("status = %q, want ok; body: %s", response.Status, recorder.Body.String())
	}

	if len(response.Data) == 0 {
		t.Fatal("expected niro-test records in response")
	}
	for _, record := range response.Data {
		if record.Organization != "niro-test" {
			t.Fatalf("org admin read record outside tenant: organization=%q owner=%q user=%q uri=%q", record.Organization, record.Owner, record.User, record.RequestUri)
		}
	}
}
