package scim

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	_ "unsafe"

	"github.com/beego/beego/v2/server/web"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/casdoor/casdoor/object"
	elimity "github.com/elimity-com/scim"
	"github.com/scim2/filter-parser/v2"
)

const testRequesterOrganizationKey = "casdoorScimRequesterOrganization"

//go:linkname objectCreateDatabase github.com/casdoor/casdoor/object.createDatabase
var objectCreateDatabase bool

//go:linkname objectUserEnforcer github.com/casdoor/casdoor/object.userEnforcer
var objectUserEnforcer *object.UserGroupEnforcer

func TestTenantScopedSCIMUserHandlersRejectCrossOrganizationAccess(t *testing.T) {
	setupTenantScopeTestDB(t)

	handler := UserResourceHandler{}
	tenantReq := requestWithTenantScope("niro-test")
	globalReq := requestWithTenantScope("")

	page, err := handler.GetAll(globalReq, elimity.ListRequestParams{StartIndex: 1, Count: 100})
	if err != nil {
		t.Fatalf("global admin list returned error: %v", err)
	}
	if !pageContainsUser(page, "admin", "built-in") {
		t.Fatalf("global admin list did not include built-in/admin control resource: %+v", page.Resources)
	}

	page, err = handler.GetAll(tenantReq, elimity.ListRequestParams{StartIndex: 1, Count: 100})
	if err == nil && pageContainsOrganization(page, "built-in") {
		t.Fatalf("tenant admin listed cross-organization SCIM users; got built-in resources in %+v", page.Resources)
	}

	_, err = handler.Patch(tenantReq, "built-in-admin-id", []elimity.PatchOperation{{
		Op:    elimity.PatchOperationReplace,
		Path:  mustPatchPath(t, "displayName"),
		Value: "Admin",
	}})
	if err == nil {
		t.Fatalf("tenant admin patched cross-organization user built-in/admin; expected authorization error")
	}

	replaceAttrs := scimUserAttrs("tenant-move", "built-in")
	_, err = handler.Replace(tenantReq, "niro-user-id", replaceAttrs)
	if err == nil {
		t.Fatalf("tenant admin moved niro-test user into built-in via SCIM replace; expected authorization error")
	}

	_, err = handler.Create(tenantReq, scimUserAttrs("tenant-cross-create", "built-in"))
	if err == nil {
		t.Fatalf("tenant admin created a built-in SCIM user; expected authorization error")
	}

	created, err := handler.Create(tenantReq, scimUserAttrs("tenant-same-create", "niro-test"))
	if err != nil {
		t.Fatalf("tenant admin same-organization SCIM create failed: %v", err)
	}
	if got := resourceOrganization(created, UserExtensionKey); got != "niro-test" {
		t.Fatalf("same-organization SCIM create organization = %q, want niro-test", got)
	}
}

func TestTenantScopedSCIMGroupHandlersRejectCrossOrganizationDelete(t *testing.T) {
	setupTenantScopeTestDB(t)

	handler := GroupResourceHandler{}
	tenantReq := requestWithTenantScope("niro-test")
	globalReq := requestWithTenantScope("")

	if _, err := handler.Get(globalReq, "built-in/global-group"); err != nil {
		t.Fatalf("global admin get built-in group control failed: %v", err)
	}

	err := handler.Delete(tenantReq, "built-in/global-group")
	if err == nil {
		t.Fatalf("tenant admin deleted cross-organization group built-in/global-group; expected authorization error")
	}
}

func setupTenantScopeTestDB(t *testing.T) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "casdoor-scim-test.db")
	confPath := filepath.Join(t.TempDir(), "app.conf")
	conf := fmt.Sprintf("appname = casdoor\ndriverName = sqlite\ndataSourceName = file:%s?cache=shared\ndbName = casdoor\ncreateDatabase = true\nshowSql = false\n", dbPath)
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := web.LoadAppConfig("ini", confPath); err != nil {
		t.Fatal(err)
	}
	web.BConfig.WebConfig.Session.SessionOn = true
	objectCreateDatabase = false
	object.InitAdapter()
	object.CreateTables()
	initGroupEnforcer(t)

	addOrganization(t, "built-in", true)
	addOrganization(t, "niro-test", false)
	addApplication(t, "app-niro-test", "niro-test")
	addUser(t, "built-in", "admin", "built-in-admin-id", true)
	addUser(t, "niro-test", "org-admin", "niro-admin-id", true)
	addUser(t, "niro-test", "alice", "niro-user-id", false)
	addGroup(t, "built-in", "global-group")
}

func initGroupEnforcer(t *testing.T) {
	t.Helper()
	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj
[policy_definition]
p = sub, obj
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = true
`)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(policyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	enforcer, err := casbin.NewSyncedEnforcer(m, fileadapter.NewAdapter(policyPath))
	if err != nil {
		t.Fatal(err)
	}
	objectUserEnforcer = object.NewUserGroupEnforcer(enforcer)
}

func requestWithTenantScope(organization string) *http.Request {
	req := httptestRequest()
	return req.WithContext(context.WithValue(req.Context(), testRequesterOrganizationKey, organization))
}

func httptestRequest() *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/scim/Users", nil)
	return req
}

func addOrganization(t *testing.T, name string, hasPrivilegeConsent bool) {
	t.Helper()
	_, err := object.AddOrganization(&object.Organization{
		Owner:               "admin",
		Name:                name,
		DisplayName:         name,
		HasPrivilegeConsent: hasPrivilegeConsent,
		PasswordType:        "plain",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func addApplication(t *testing.T, name string, organization string) {
	t.Helper()
	_, err := object.AddApplication(&object.Application{
		Owner:        "admin",
		Name:         name,
		DisplayName:  name,
		Organization: organization,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func addUser(t *testing.T, owner string, name string, id string, isAdmin bool) {
	t.Helper()
	_, err := object.AddUser(&object.User{
		Owner:       owner,
		Name:        name,
		Id:          id,
		DisplayName: name,
		Password:    "password",
		IsAdmin:     isAdmin,
	}, "en")
	if err != nil {
		t.Fatal(err)
	}
}

func addGroup(t *testing.T, owner string, name string) {
	t.Helper()
	_, err := object.AddGroup(&object.Group{
		Owner:       owner,
		Name:        name,
		DisplayName: name,
		IsTopGroup:  true,
		IsEnabled:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func scimUserAttrs(username string, organization string) elimity.ResourceAttributes {
	return elimity.ResourceAttributes{
		"userName":    username,
		"displayName": username,
		UserExtensionKey: map[string]interface{}{
			"organization": organization,
		},
	}
}

func pageContainsUser(page elimity.Page, username string, organization string) bool {
	for _, resource := range page.Resources {
		if got, _ := resource.Attributes["userName"].(string); got == username && resourceOrganization(resource, UserExtensionKey) == organization {
			return true
		}
	}
	return false
}

func pageContainsOrganization(page elimity.Page, organization string) bool {
	for _, resource := range page.Resources {
		if resourceOrganization(resource, UserExtensionKey) == organization {
			return true
		}
	}
	return false
}

func resourceOrganization(resource elimity.Resource, extensionKey string) string {
	extension, ok := resource.Attributes[extensionKey].(elimity.ResourceAttributes)
	if !ok {
		return ""
	}
	org, _ := extension["organization"].(string)
	return org
}

func mustPatchPath(t *testing.T, value string) *filter.Path {
	t.Helper()
	path, err := filter.ParsePath([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return &path
}
