package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	_ "unsafe"

	"github.com/beego/beego/v2/server/web"
	webcontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var readAuthInitOnce sync.Once

//go:linkname objectCreateDatabase github.com/casdoor/casdoor/object.createDatabase
var objectCreateDatabase bool

type responseEnvelope struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func initReadAuthTest(t *testing.T) {
	t.Helper()

	readAuthInitOnce.Do(func() {
		configPath := filepath.Join(t.TempDir(), "app.conf")
		config := "appname = casdoor\n" +
			"runmode = test\n" +
			"copyrequestbody = true\n" +
			"driverName = sqlite\n" +
			"dataSourceName = file:read_authorization_test?mode=memory&cache=shared\n" +
			"dbName = casdoor\n" +
			"tableNamePrefix =\n" +
			"defaultLanguage = en\n" +
			"enableErrorMask2 = false\n" +
			"defaultApplication = app-built-in\n" +
			"initScore = 0\n"
		if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}
		if err := web.LoadAppConfig("ini", configPath); err != nil {
			t.Fatalf("load test config: %v", err)
		}
		web.BConfig.WebConfig.Session.SessionOn = true
		objectCreateDatabase = false
		object.InitAdapter()
		object.CreateTables()
		object.InitDb()
	})
}

func TestReadHandlersRejectAnonymousCustomerDataAccess(t *testing.T) {
	initReadAuthTest(t)

	owner := "read-auth-" + util.GenerateId()[:8]
	userName := "bob"
	userId := util.GetId(owner, userName)
	email := userName + "@" + owner + ".example.com"

	org := &object.Organization{
		Owner:           "admin",
		Name:            owner,
		DisplayName:     "Read authorization test",
		IsProfilePublic: true,
	}
	if _, err := object.AddOrganization(org); err != nil {
		t.Fatalf("add organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteOrganization(org)
	})

	application := &object.Application{
		Owner:        "admin",
		Name:         "app-" + owner,
		DisplayName:  "Read authorization app",
		Organization: owner,
		EnableSignUp: true,
	}
	if _, err := object.AddApplication(application); err != nil {
		t.Fatalf("add application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteApplication(application)
	})

	user := &object.User{
		Owner:        owner,
		Name:         userName,
		DisplayName:  "Bob",
		Email:        email,
		Phone:        "10000000002",
		PasswordSalt: "test-password-salt",
		CreatedIp:    "127.0.0.1",
	}
	if _, err := object.AddUser(user, "en"); err != nil {
		t.Fatalf("add user: %v", err)
	}

	subscription := &object.Subscription{
		Owner:       owner,
		Name:        "sub-" + util.GenerateId()[:8],
		DisplayName: "Private subscription",
		User:        userName,
		Pricing:     "internal-pricing",
		Plan:        "internal-plan",
		Payment:     "private-payment-reference",
		StartTime:   "2026-07-17T00:00:00Z",
		EndTime:     "2026-08-17T00:00:00Z",
		Period:      "Monthly",
		State:       object.SubStateActive,
	}
	if _, err := object.AddSubscription(subscription); err != nil {
		t.Fatalf("add subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteSubscription(subscription)
	})

	t.Run("anonymous user profile lookup is denied", func(t *testing.T) {
		resp := callReadHandler(t, http.MethodGet, "/api/get-user?email="+email, "", (*ApiController).GetUser)
		assertError(t, resp)
		assertNoUserProfileFields(t, resp)
	})

	t.Run("authenticated self user profile lookup still works", func(t *testing.T) {
		resp := callReadHandler(t, http.MethodGet, "/api/get-user?email="+email, userId, (*ApiController).GetUser)
		assertOk(t, resp)

		var got object.User
		if err := json.Unmarshal(resp.Data, &got); err != nil {
			t.Fatalf("decode user response: %v", err)
		}
		if got.GetId() != userId || got.Email != email || got.Phone != user.Phone {
			t.Fatalf("self profile response = id:%q email:%q phone:%q, want id:%q email:%q phone:%q", got.GetId(), got.Email, got.Phone, userId, email, user.Phone)
		}
	})

	t.Run("anonymous subscription lookup is denied", func(t *testing.T) {
		resp := callReadHandler(t, http.MethodGet, "/api/get-subscription?id="+subscription.GetId(), "", (*ApiController).GetSubscription)
		assertError(t, resp)
		assertNoSubscriptionFields(t, resp)
	})

	t.Run("own subscription lookup still works", func(t *testing.T) {
		resp := callReadHandler(t, http.MethodGet, "/api/get-subscription?id="+subscription.GetId(), userId, (*ApiController).GetSubscription)
		assertOk(t, resp)

		var got object.Subscription
		if err := json.Unmarshal(resp.Data, &got); err != nil {
			t.Fatalf("decode subscription response: %v", err)
		}
		if got.GetId() != subscription.GetId() || got.User != userName || got.Payment != subscription.Payment {
			t.Fatalf("own subscription response = id:%q user:%q payment:%q, want id:%q user:%q payment:%q", got.GetId(), got.User, got.Payment, subscription.GetId(), userName, subscription.Payment)
		}
	})
}

func callReadHandler(t *testing.T, method string, target string, sessionUser string, handler func(*ApiController)) responseEnvelope {
	t.Helper()

	request := httptest.NewRequest(method, target, nil)
	recorder := httptest.NewRecorder()
	ctx := webcontext.NewContext()
	ctx.Reset(recorder, request)

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "", controller)
	controller.Ctx.Input.SetData("currentUserId", sessionUser)

	handler(controller)

	var resp responseEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return resp
}

func assertOk(t *testing.T, resp responseEnvelope) {
	t.Helper()

	if resp.Status != "ok" {
		t.Fatalf("status = %q msg = %q, want ok", resp.Status, resp.Msg)
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		t.Fatalf("expected response data, got %s", string(resp.Data))
	}
}

func assertError(t *testing.T, resp responseEnvelope) {
	t.Helper()

	if resp.Status != "error" {
		t.Fatalf("status = %q data = %s, want error without customer data", resp.Status, string(resp.Data))
	}
}

func assertNoUserProfileFields(t *testing.T, resp responseEnvelope) {
	t.Helper()

	for _, field := range []string{"email", "phone", "passwordSalt", "createdIp"} {
		if string(resp.Data) != "" && jsonContainsField(resp.Data, field) {
			t.Fatalf("anonymous profile response exposed %q in %s", field, string(resp.Data))
		}
	}
}

func assertNoSubscriptionFields(t *testing.T, resp responseEnvelope) {
	t.Helper()

	for _, field := range []string{"user", "plan", "payment", "state"} {
		if string(resp.Data) != "" && jsonContainsField(resp.Data, field) {
			t.Fatalf("anonymous subscription response exposed %q in %s", field, string(resp.Data))
		}
	}
}

func jsonContainsField(raw json.RawMessage, field string) bool {
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return false
	}
	_, ok := data[field]
	return ok
}
