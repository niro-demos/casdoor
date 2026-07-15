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

package controllers

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// Regression tests for TC-D88C1B09, TC-B919E08F and TC-DEFC6A99: even once
// the Casbin self-service bypass can no longer be gamed via a body "user"
// field that differs from the caller (see routers/authz_filter_test.go),
// the bypass still legitimately lets a caller act on a subscription/
// transaction/token row that genuinely is their own. These tests cover the
// business-logic guards that stop a non-admin caller from abusing that
// self-service path: minting an unpaid Active subscription, minting
// unverified balance, or forging their own token row's "user" field to
// impersonate someone else.
//
// Fixtures are created directly through the object package's own factory
// functions (mirroring object/init.go's built-in bootstrap), under a
// dedicated test organization, so these tests never touch or depend on any
// pentest-harness-seeded data.

const (
	authzTestOrgName   = "niro-remediation-test-org"
	authzTestAppName   = "niro-remediation-test-app"
	authzTestAdminName = "niro-remediation-admin"
	authzTestUserAName = "niro-remediation-alice"
	authzTestUserBName = "niro-remediation-bob"
)

type authzTestFixtures struct {
	orgId   string
	adminId string
	userAId string
	userBId string
}

func setupAuthzBusinessRuleFixtures(t *testing.T) authzTestFixtures {
	t.Helper()

	object.InitConfig()
	object.InitDb()
	object.InitUserManager()

	org := &object.Organization{
		Owner:           "admin",
		Name:            authzTestOrgName,
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     authzTestOrgName,
		PasswordType:    "plain",
		PasswordOptions: []string{"AtLeast6"},
		CountryCodes:    []string{"US"},
		InitScore:       0,
		AccountItems:    object.GetDefaultAccountItems(),
	}
	if ok, err := object.AddOrganization(org); err != nil {
		t.Fatalf("failed to create test organization: %v", err)
	} else if !ok {
		t.Fatalf("test organization already existed from a prior unclean run; delete owner=admin name=%s and re-run", authzTestOrgName)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteOrganization(org)
	})

	app := &object.Application{
		Owner:          "admin",
		Name:           authzTestAppName,
		CreatedTime:    util.GetCurrentTime(),
		DisplayName:    authzTestAppName,
		Organization:   authzTestOrgName,
		EnablePassword: true,
	}
	if ok, err := object.AddApplication(app); err != nil {
		t.Fatalf("failed to create test application: %v", err)
	} else if !ok {
		t.Fatalf("failed to create test application (already existed)")
	}
	t.Cleanup(func() {
		_, _ = object.DeleteApplication(app)
	})

	newUser := func(name string, isAdmin bool) *object.User {
		user := &object.User{
			Owner:             authzTestOrgName,
			Name:              name,
			Id:                util.GenerateId(),
			Type:              "normal-user",
			Password:          "Niro-Test-Pw1!",
			DisplayName:       name,
			SignupApplication: authzTestAppName,
			IsAdmin:           isAdmin,
		}
		if _, err := object.AddUser(user, "en"); err != nil {
			t.Fatalf("failed to create test user %s: %v", name, err)
		}
		t.Cleanup(func() {
			_, _ = object.DeleteUser(user)
		})
		return user
	}

	admin := newUser(authzTestAdminName, true)
	userA := newUser(authzTestUserAName, false)
	userB := newUser(authzTestUserBName, false)

	return authzTestFixtures{
		orgId:   authzTestOrgName,
		adminId: admin.GetId(),
		userAId: userA.GetId(),
		userBId: userB.GetId(),
	}
}

// newTestApiController builds an ApiController the way ApiFilter would leave
// it for a handler: with the resolved caller identity already stashed in
// the request context, and the raw JSON body cached exactly like
// RequestBodyFilter does.
func newTestApiController(t *testing.T, method, path, body, currentUserId string) *ApiController {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ctx := context.NewContext()
	ctx.Reset(rec, req)
	ctx.Input.RequestBody = []byte(body)
	ctx.Input.SetData("currentUserId", currentUserId)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "Test", nil)
	return c
}

// TestAddSubscriptionRequiresAdmin is the regression test for TC-D88C1B09:
// a standard user must not be able to self-grant or gift an active paid
// subscription via POST /api/add-subscription with no payment behind it.
func TestAddSubscriptionRequiresAdmin(t *testing.T) {
	f := setupAuthzBusinessRuleFixtures(t)

	cleanupSubscription := func(name string) {
		_, _ = object.DeleteSubscription(&object.Subscription{Owner: f.orgId, Name: name})
	}

	t.Run("standard user cannot self-grant an active subscription", func(t *testing.T) {
		body := fmt.Sprintf(`{"owner":%q,"name":%q,"displayName":"niro-selfgrant","user":%q,"state":"Active","startTime":"2026-01-01T00:00:00Z","endTime":"2030-01-01T00:00:00Z","period":"Monthly"}`,
			f.orgId, authzTestUserAName, authzTestUserAName)
		defer cleanupSubscription(authzTestUserAName)

		c := newTestApiController(t, "POST", "/api/add-subscription", body, f.userAId)
		c.AddSubscription()

		resp, ok := c.Data["json"].(*Response)
		if !ok || resp.Status != "error" {
			t.Fatalf("VULNERABLE: standard user self-granted a subscription: %#v", c.Data["json"])
		}

		sub, err := object.GetSubscription(f.orgId + "/" + authzTestUserAName)
		if err != nil {
			t.Fatalf("GetSubscription error: %v", err)
		}
		if sub != nil {
			t.Fatalf("VULNERABLE: subscription record was persisted despite the denial: %#v", sub)
		}
	})

	t.Run("standard user cannot gift an active subscription to another user", func(t *testing.T) {
		body := fmt.Sprintf(`{"owner":%q,"name":%q,"displayName":"niro-gift","user":%q,"state":"Active","startTime":"2026-01-01T00:00:00Z","endTime":"2030-01-01T00:00:00Z","period":"Monthly"}`,
			f.orgId, authzTestUserAName, authzTestUserBName)
		defer cleanupSubscription(authzTestUserAName)

		c := newTestApiController(t, "POST", "/api/add-subscription", body, f.userAId)
		c.AddSubscription()

		resp, ok := c.Data["json"].(*Response)
		if !ok || resp.Status != "error" {
			t.Fatalf("VULNERABLE: standard user gifted a subscription to another account: %#v", c.Data["json"])
		}
	})

	t.Run("control: admin can still add a subscription", func(t *testing.T) {
		body := fmt.Sprintf(`{"owner":%q,"name":%q,"displayName":"niro-admin-add","user":%q,"state":"Active","startTime":"2026-01-01T00:00:00Z","endTime":"2030-01-01T00:00:00Z","period":"Monthly"}`,
			f.orgId, authzTestAdminName, authzTestUserAName)
		defer cleanupSubscription(authzTestAdminName)

		c := newTestApiController(t, "POST", "/api/add-subscription", body, f.adminId)
		c.AddSubscription()

		resp, ok := c.Data["json"].(*Response)
		if !ok || resp.Status != "ok" {
			t.Fatalf("admin add-subscription unexpectedly denied: %#v", c.Data["json"])
		}
	})
}

// TestAddTransactionRequiresAdminForLiveCredit is the regression test for
// TC-B919E08F: a standard user must not be able to directly credit their
// own or another account's balance via POST /api/add-transaction.
func TestAddTransactionRequiresAdminForLiveCredit(t *testing.T) {
	f := setupAuthzBusinessRuleFixtures(t)
	t.Cleanup(func() {
		// Belt-and-suspenders: purge any transaction row this test managed
		// to create under the dedicated test org, whether the run ended up
		// red or green.
		transactions, err := object.GetTransactions(f.orgId)
		if err != nil {
			return
		}
		for _, tx := range transactions {
			_, _ = object.DeleteTransaction(tx, "en")
		}
	})

	getBalance := func(userId string) float64 {
		u, err := object.GetUser(userId)
		if err != nil {
			t.Fatalf("GetUser(%s) error: %v", userId, err)
		}
		if u == nil {
			t.Fatalf("GetUser(%s) returned nil", userId)
		}
		return u.Balance
	}

	t.Run("standard user cannot self-credit balance", func(t *testing.T) {
		before := getBalance(f.userAId)

		body := fmt.Sprintf(`{"owner":%q,"name":%q,"application":%q,"category":"Recharge","type":"Recharge","user":%q,"tag":"User","amount":424242,"currency":"USD","state":"Success"}`,
			f.orgId, authzTestUserAName, authzTestAppName, authzTestUserAName)
		c := newTestApiController(t, "POST", "/api/add-transaction", body, f.userAId)
		c.AddTransaction()

		resp, ok := c.Data["json"].(*Response)
		if !ok || resp.Status != "error" {
			t.Fatalf("VULNERABLE: standard user self-credited via add-transaction: %#v", c.Data["json"])
		}

		after := getBalance(f.userAId)
		if after != before {
			t.Fatalf("VULNERABLE: balance changed from %v to %v despite the denial", before, after)
		}
	})

	t.Run("standard user cannot credit another user's balance", func(t *testing.T) {
		before := getBalance(f.userBId)

		body := fmt.Sprintf(`{"owner":%q,"name":%q,"application":%q,"category":"Recharge","type":"Recharge","user":%q,"tag":"User","amount":131313,"currency":"USD","state":"Success"}`,
			f.orgId, authzTestUserAName, authzTestAppName, authzTestUserBName)
		c := newTestApiController(t, "POST", "/api/add-transaction", body, f.userAId)
		c.AddTransaction()

		resp, ok := c.Data["json"].(*Response)
		if !ok || resp.Status != "error" {
			t.Fatalf("VULNERABLE: standard user credited a peer's balance via add-transaction: %#v", c.Data["json"])
		}

		after := getBalance(f.userBId)
		if after != before {
			t.Fatalf("VULNERABLE: bob's balance changed from %v to %v despite the denial", before, after)
		}
	})

	t.Run("control: admin can still add a live transaction", func(t *testing.T) {
		before := getBalance(f.userAId)

		body := fmt.Sprintf(`{"owner":%q,"name":%q,"application":%q,"category":"Recharge","type":"Recharge","user":%q,"tag":"User","amount":100,"currency":"USD","state":"Success"}`,
			f.orgId, authzTestAdminName, authzTestAppName, authzTestUserAName)
		c := newTestApiController(t, "POST", "/api/add-transaction", body, f.adminId)
		c.AddTransaction()

		resp, ok := c.Data["json"].(*Response)
		if !ok || resp.Status != "ok" {
			t.Fatalf("admin add-transaction unexpectedly denied: %#v", c.Data["json"])
		}

		after := getBalance(f.userAId)
		if after != before+100 {
			t.Fatalf("admin add-transaction did not credit balance as expected: before=%v after=%v", before, after)
		}
	})
}

// TestTokenUpdateRequiresOwnUser is the regression test for TC-DEFC6A99: a
// standard user must not be able to forge their own Token row's "user"
// field to a different, more privileged account.
func TestTokenUpdateRequiresOwnUser(t *testing.T) {
	f := setupAuthzBusinessRuleFixtures(t)
	defer func() {
		_, _ = object.DeleteToken(&object.Token{Owner: f.orgId, Name: authzTestUserAName, Organization: f.orgId})
	}()

	// Establish a legitimate self-owned token row first (positive control:
	// a standard user creating/using their own token must keep working).
	addBody := fmt.Sprintf(`{"owner":%q,"name":%q,"organization":%q,"application":%q,"user":%q,"accessToken":"niro-legit-at","refreshToken":"niro-legit-rt","expiresIn":3600,"tokenType":"Bearer"}`,
		f.orgId, authzTestUserAName, f.orgId, authzTestAppName, authzTestUserAName)
	addCtl := newTestApiController(t, "POST", "/api/add-token", addBody, f.userAId)
	addCtl.AddToken()
	if resp, ok := addCtl.Data["json"].(*Response); !ok || resp.Status != "ok" {
		t.Fatalf("control failed: standard user could not create their own token row: %#v", addCtl.Data["json"])
	}

	t.Run("standard user cannot forge the user field to impersonate another account", func(t *testing.T) {
		forgeBody := fmt.Sprintf(`{"owner":%q,"name":%q,"organization":%q,"application":%q,"user":%q,"accessToken":"niro-forged-at","refreshToken":"niro-forged-rt","expiresIn":3600,"tokenType":"Bearer"}`,
			f.orgId, authzTestUserAName, f.orgId, authzTestAppName, authzTestAdminName)
		id := f.orgId + "/" + authzTestUserAName
		c := newTestApiController(t, "POST", "/api/update-token?id="+id, forgeBody, f.userAId)
		c.Ctx.Input.SetParam("id", id)
		c.UpdateToken()

		resp, ok := c.Data["json"].(*Response)
		if !ok || resp.Status != "error" {
			t.Fatalf("VULNERABLE: standard user forged their token's user field to impersonate %s: %#v", authzTestAdminName, c.Data["json"])
		}

		tok, err := object.GetToken(id)
		if err != nil {
			t.Fatalf("GetToken error: %v", err)
		}
		if tok == nil {
			t.Fatalf("expected the token row created by the control step to still exist")
		}
		if tok.User != authzTestUserAName {
			t.Fatalf("VULNERABLE: token row's user field was changed to %q despite the denial", tok.User)
		}
	})

	t.Run("control: admin can update a token's user field", func(t *testing.T) {
		updateBody := fmt.Sprintf(`{"owner":%q,"name":%q,"organization":%q,"application":%q,"user":%q,"accessToken":"niro-admin-updated-at","refreshToken":"niro-admin-updated-rt","expiresIn":3600,"tokenType":"Bearer"}`,
			f.orgId, authzTestUserAName, f.orgId, authzTestAppName, authzTestUserAName)
		id := f.orgId + "/" + authzTestUserAName
		c := newTestApiController(t, "POST", "/api/update-token?id="+id, updateBody, f.adminId)
		c.Ctx.Input.SetParam("id", id)
		c.UpdateToken()

		resp, ok := c.Data["json"].(*Response)
		if !ok || resp.Status != "ok" {
			t.Fatalf("admin update-token unexpectedly denied: %#v", c.Data["json"])
		}
	})
}
