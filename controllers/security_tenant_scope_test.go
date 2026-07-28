package controllers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	beegoctx "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	casdoorscim "github.com/casdoor/casdoor/scim"
	"github.com/casdoor/casdoor/util"
)

func TestMain(m *testing.M) {
	root, err := filepath.Abs("..")
	if err != nil {
		panic(err)
	}
	if err := os.Chdir(root); err != nil {
		panic(err)
	}

	dbPath := filepath.Join(os.TempDir(), "casdoor-controller-tenant-scope.sqlite")
	_ = os.Remove(dbPath)
	_ = os.Setenv("driverName", "sqlite")
	_ = os.Setenv("dataSourceName", "file:"+dbPath+"?cache=shared")
	_ = os.Setenv("dbName", "")
	_ = os.Setenv("initDataFile", "")
	object.InitFlag()
	object.InitAdapter()
	object.CreateTables()
	seedControllerTenantScopeData()

	code := m.Run()
	_ = os.Remove(dbPath)
	os.Exit(code)
}

func seedControllerTenantScopeData() {
	for _, org := range []string{"niro-alpha", "niro-beta"} {
		_, err := object.AddOrganization(&object.Organization{
			Owner:       "admin",
			Name:        org,
			CreatedTime: util.GetCurrentTime(),
			DisplayName: org,
		})
		if err != nil {
			panic(err)
		}
		_, err = object.AddApplication(&object.Application{
			Owner:        "admin",
			Name:         "app-" + org,
			CreatedTime:  util.GetCurrentTime(),
			DisplayName:  "app-" + org,
			Organization: org,
		})
		if err != nil {
			panic(err)
		}
	}

	for _, user := range []*object.User{
		{Owner: "niro-alpha", Name: "admin", DisplayName: "Alpha Admin", IsAdmin: true, Password: "pass"},
		{Owner: "niro-alpha", Name: "alice", DisplayName: "Alpha Alice", Id: "alpha-alice-id", Email: "alpha-alice@example.test", Password: "pass"},
		{Owner: "niro-beta", Name: "admin", DisplayName: "Beta Admin", IsAdmin: true, Password: "pass"},
		{Owner: "niro-beta", Name: "alice", DisplayName: "Beta Alice", Password: "pass"},
		{Owner: "niro-beta", Name: "bob", DisplayName: "Beta Bob", Id: "beta-bob-id", Email: "beta-bob@example.test", Password: "pass"},
	} {
		_, err := object.AddUser(user, "en")
		if err != nil {
			panic(err)
		}
	}

	_, err := object.AddResource(&object.Resource{
		Owner:       "niro-alpha",
		Name:        "scoutlife-resource",
		CreatedTime: util.GetCurrentTime(),
		User:        "alice",
		FileName:    "scoutlife.txt",
		FileSize:    1,
	})
	if err != nil {
		panic(err)
	}

	for _, record := range []*object.Record{
		{Organization: "niro-alpha", Name: "alpha-record", CreatedTime: util.GetCurrentTime(), User: "alice", Method: http.MethodGet, RequestUri: "/api/alpha", Action: "alpha", StatusCode: http.StatusOK},
		{Organization: "niro-beta", Name: "beta-record", CreatedTime: util.GetCurrentTime(), User: "alice", Method: http.MethodPost, RequestUri: "/api/beta", Action: "beta", StatusCode: http.StatusOK},
	} {
		if ok := object.AddRecord(record); !ok {
			panic("failed to add test record")
		}
	}
}

func TestGetResourcesScopesNonAdminToAuthenticatedTenant(t *testing.T) {
	own := performAPIRequest("niro-alpha/alice", http.MethodGet, "/api/get-resources?owner=niro-alpha&user=alice", func(c *ApiController) {
		c.GetResources()
	})
	var ownResp struct {
		Status string             `json:"status"`
		Data   []*object.Resource `json:"data"`
	}
	decodeControllerResponse(t, own, &ownResp)
	if !containsResource(ownResp.Data, "niro-alpha", "alice", "scoutlife-resource") {
		t.Fatalf("positive control failed: alpha alice could not read her own resource: %+v", ownResp.Data)
	}

	cross := performAPIRequest("niro-beta/alice", http.MethodGet, "/api/get-resources?owner=niro-alpha&user=alice", func(c *ApiController) {
		c.GetResources()
	})
	var crossResp struct {
		Status string             `json:"status"`
		Data   []*object.Resource `json:"data"`
	}
	decodeControllerResponse(t, cross, &crossResp)
	if containsResource(crossResp.Data, "niro-alpha", "alice", "scoutlife-resource") {
		t.Fatalf("tenant isolation violated: beta alice read alpha resource metadata: %+v", crossResp.Data)
	}
}

func TestGetRecordsWithoutPaginationScopesTenantAdmin(t *testing.T) {
	resp := performAPIRequest("niro-alpha/admin", http.MethodGet, "/api/get-records", func(c *ApiController) {
		c.GetRecords()
	})
	var payload struct {
		Status string           `json:"status"`
		Data   []*object.Record `json:"data"`
	}
	decodeControllerResponse(t, resp, &payload)
	for _, record := range payload.Data {
		if record.Organization != "niro-alpha" {
			t.Fatalf("tenant isolation violated: alpha admin read %q audit record %+v", record.Organization, record)
		}
	}
	if len(payload.Data) == 0 {
		t.Fatalf("positive control failed: expected at least one alpha audit record")
	}
}

func TestHandleScimScopesUsersToAuthenticatedTenant(t *testing.T) {
	list := performRootRequest("niro-alpha/admin", http.MethodGet, "/scim/Users?startIndex=1&count=100", "application/scim+json", nil, func(c *RootController) {
		c.HandleScim()
	})
	if list.Code != http.StatusOK {
		t.Fatalf("SCIM list status = %d, body = %s", list.Code, list.Body.String())
	}
	var page struct {
		Resources []map[string]interface{} `json:"Resources"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode SCIM list: %v; body = %s", err, list.Body.String())
	}
	if len(page.Resources) == 0 {
		t.Fatalf("positive control failed: expected alpha users in SCIM list")
	}
	for _, resource := range page.Resources {
		if org := scimResourceOrganization(resource); org != "niro-alpha" {
			t.Fatalf("tenant isolation violated: alpha admin listed %q SCIM user %+v", org, resource)
		}
	}

	createOwn := performRootRequest("niro-alpha/admin", http.MethodPost, "/scim/Users", "application/scim+json", scimUserBody("niro-alpha", "alpha-owned-scim"), func(c *RootController) {
		c.HandleScim()
	})
	if createOwn.Code != http.StatusCreated {
		t.Fatalf("positive control failed: alpha admin create alpha SCIM user status = %d, body = %s", createOwn.Code, createOwn.Body.String())
	}

	createCross := performRootRequest("niro-alpha/admin", http.MethodPost, "/scim/Users", "application/scim+json", scimUserBody("niro-beta", "alpha-cross-beta-scim"), func(c *RootController) {
		c.HandleScim()
	})
	if createCross.Code >= 200 && createCross.Code < 300 {
		t.Fatalf("tenant isolation violated: alpha admin created beta SCIM user, status = %d, body = %s", createCross.Code, createCross.Body.String())
	}

	getCross := performRootRequest("niro-alpha/admin", http.MethodGet, "/scim/Users/beta-bob-id", "application/scim+json", nil, func(c *RootController) {
		c.HandleScim()
	})
	if getCross.Code >= 200 && getCross.Code < 300 {
		t.Fatalf("tenant isolation violated: alpha admin read beta SCIM user, status = %d, body = %s", getCross.Code, getCross.Body.String())
	}

	deleteCross := performRootRequest("niro-alpha/admin", http.MethodDelete, "/scim/Users/beta-bob-id", "application/scim+json", nil, func(c *RootController) {
		c.HandleScim()
	})
	if deleteCross.Code >= 200 && deleteCross.Code < 300 {
		t.Fatalf("tenant isolation violated: alpha admin deleted beta SCIM user, status = %d", deleteCross.Code)
	}
}

func performAPIRequest(userID string, method string, target string, run func(c *ApiController)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	recorder := httptest.NewRecorder()
	ctx := beegoctx.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.SetData("currentUserId", userID)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", controller)
	run(controller)
	return recorder
}

func performRootRequest(userID string, method string, target string, contentType string, body []byte, run func(c *RootController)) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RequestURI = target
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Accept", contentType)
	}
	recorder := httptest.NewRecorder()
	ctx := beegoctx.NewContext()
	ctx.Reset(recorder, req)
	ctx.Input.SetData("currentUserId", userID)
	if body != nil {
		ctx.Input.RequestBody = body
	}

	controller := &RootController{}
	controller.Init(ctx, "RootController", "", controller)
	run(controller)
	return recorder
}

func decodeControllerResponse(t *testing.T, recorder *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), target); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, recorder.Body.String())
	}
}

func containsResource(resources []*object.Resource, owner string, user string, name string) bool {
	for _, resource := range resources {
		if resource.Owner == owner && resource.User == user && resource.Name == name {
			return true
		}
	}
	return false
}

func scimUserBody(organization string, username string) []byte {
	body := map[string]interface{}{
		"schemas": []string{
			"urn:ietf:params:scim:schemas:core:2.0:User",
			casdoorscim.UserExtensionKey,
		},
		"userName":    username,
		"displayName": username,
		"active":      true,
		"emails": []map[string]interface{}{
			{"value": username + "@example.test", "primary": true},
		},
		casdoorscim.UserExtensionKey: map[string]string{
			"organization": organization,
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return raw
}

func scimResourceOrganization(resource map[string]interface{}) string {
	extension, ok := resource[casdoorscim.UserExtensionKey].(map[string]interface{})
	if !ok {
		return ""
	}
	org, _ := extension["organization"].(string)
	return strings.TrimSpace(org)
}
