// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"net/http/httptest"
	"testing"

	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// callGetCerts drives the real ApiController.GetCerts handler as
// "GET /api/get-certs?owner=<owner>" would, with the session pinned to
// sessionUser (an "owner/name" user id). It bypasses the HTTP router/session
// store by writing straight to the same beego context field
// (Input.GetData("currentUserId")) that ApiController.GetSessionUsername
// reads first - the same mechanism the real ApiFilter session middleware
// uses to attribute a request to a signed-in user.
func callGetCerts(t *testing.T, sessionUser, owner string) []*object.Cert {
	t.Helper()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/get-certs?owner="+owner, nil)
	ctx := beecontext.NewContext()
	ctx.Reset(w, r)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetCerts", nil)
	c.Ctx.Input.SetData("currentUserId", sessionUser)

	c.GetCerts()

	resp, ok := c.Data["json"].(*Response)
	if !ok {
		t.Fatalf("GetCerts as %q (owner=%q) produced no JSON response: %+v", sessionUser, owner, c.Data["json"])
	}
	if resp.Status != "ok" {
		t.Fatalf("GetCerts as %q (owner=%q) did not succeed: status=%q msg=%q", sessionUser, owner, resp.Status, resp.Msg)
	}

	certs, ok := resp.Data.([]*object.Cert)
	if !ok {
		t.Fatalf("GetCerts as %q (owner=%q) returned unexpected data shape: %#v", sessionUser, owner, resp.Data)
	}
	return certs
}

// TestOrgScopedAdminCannotReadGlobalCertPrivateKey is a regression test for
// TC-8036B94B: GET /api/get-certs masked privateKey/accessSecret only for
// callers that fail ApiController.IsAdmin() - which is true for ANY admin,
// including an org-scoped admin (Owner != "built-in") - instead of
// ApiController.IsGlobalAdmin() (Owner == "built-in" only). Because
// object.GetCerts unions in every globally-owned ("owner=admin") cert
// alongside the caller's own org's certs, an org-scoped admin could read the
// plaintext private key of "admin/cert-built-in", the platform-wide
// certificate that signs auth tokens for every organization on the
// instance.
//
// Invariant under test: an organization-scoped administrator (Owner !=
// "built-in") must not receive the plaintext private key of the shared,
// globally-owned platform signing certificate, even though that certificate
// is (by design) present in their org-scoped cert list.
func TestOrgScopedAdminCannotReadGlobalCertPrivateKey(t *testing.T) {
	object.InitConfig()
	// InitDb is the app's own idempotent bootstrap (same call main() makes
	// on first boot): it seeds the real "built-in" organization, the real
	// global admin "built-in/admin", and the real "admin/cert-built-in"
	// platform signing certificate (generating it on the fly if absent) -
	// exactly the fixture the finding's PoC exploited. It no-ops on
	// subsequent runs once those rows exist.
	object.InitDb()
	// Populates the package-level user-group enforcer from the
	// "built-in/user-enforcer-built-in" row InitDb just ensured exists; also
	// required so that object.DeleteUser (used in this test's cleanup)
	// doesn't dereference a nil enforcer.
	object.InitUserManager()

	// Suffix every seeded entity name with a fresh, run-unique id so this
	// test never collides with rows left behind by an interrupted prior run
	// (e.g. a previous run killed before its t.Cleanup could fire).
	suffix := util.GenerateId()
	testOrgName := "NiroTC8036B94BOrg" + suffix
	testAppName := "NiroTC8036B94BApp" + suffix
	testAdminName := "NiroTC8036B94BOrgAdmin" + suffix

	// --- Seed a dedicated org + application + org-scoped admin
	// (IsAdmin=true, Owner=testOrgName != "built-in"), mirroring the
	// finding's ACME_ORG_ADMIN fixture (a non-global admin whose Owner is
	// their own organization, not "built-in").
	testOrg := &object.Organization{
		Owner:       "admin",
		Name:        testOrgName,
		DisplayName: testOrgName,
	}
	if _, err := object.AddOrganization(testOrg); err != nil {
		t.Fatalf("failed to seed test organization: %v", err)
	}
	t.Cleanup(func() { _, _ = object.DeleteOrganization(testOrg) })

	testApp := &object.Application{
		Owner:        "admin",
		Name:         testAppName,
		Organization: testOrgName,
	}
	if _, err := object.AddApplication(testApp); err != nil {
		t.Fatalf("failed to seed test application: %v", err)
	}
	t.Cleanup(func() { _, _ = object.DeleteApplication(testApp) })

	orgAdmin := &object.User{
		Owner:   testOrgName,
		Name:    testAdminName,
		IsAdmin: true,
	}
	if _, err := object.AddUser(orgAdmin, "en"); err != nil {
		t.Fatalf("failed to seed org-scoped admin user: %v", err)
	}
	t.Cleanup(func() { _, _ = object.DeleteUser(orgAdmin) })

	// --- Act: request certs scoped to the org-scoped admin's own org, as
	// the finding's PoC does against GET /api/get-certs?owner=<their org>.
	certs := callGetCerts(t, testOrgName+"/"+testAdminName, testOrgName)

	var seenByOrgAdmin *object.Cert
	for _, c := range certs {
		if c.Owner == "admin" && c.Name == "cert-built-in" {
			seenByOrgAdmin = c
			break
		}
	}
	if seenByOrgAdmin == nil {
		t.Fatalf("expected the globally-owned admin/cert-built-in cert to be present (unioned) in the org-scoped admin's cert list, got none in %d certs", len(certs))
	}

	// --- Assert the invariant (the RED check): the org-scoped admin must
	// not receive the plaintext private key of the shared platform signing
	// certificate.
	if seenByOrgAdmin.PrivateKey != "" && seenByOrgAdmin.PrivateKey != "***" {
		t.Fatalf("SECURITY INVARIANT VIOLATED: org-scoped admin %s/%s (Owner != \"built-in\") received the plaintext private key of the shared platform signing certificate admin/cert-built-in: %q",
			testOrgName, testAdminName, seenByOrgAdmin.PrivateKey)
	}

	// --- Control (must stay green): the SAME cert, requested by the real
	// global admin (built-in/admin, Owner == "built-in"), legitimately comes
	// back with the plaintext key - proving the invariant is specifically
	// about the org-scoped admin, not that masking is broken outright.
	globalCerts := callGetCerts(t, "built-in/admin", "admin")
	var seenByGlobalAdmin *object.Cert
	for _, c := range globalCerts {
		if c.Owner == "admin" && c.Name == "cert-built-in" {
			seenByGlobalAdmin = c
			break
		}
	}
	if seenByGlobalAdmin == nil || seenByGlobalAdmin.PrivateKey == "" || seenByGlobalAdmin.PrivateKey == "***" {
		t.Fatalf("control broken: the true global admin (built-in/admin) should legitimately receive the plaintext private key for admin/cert-built-in (harness/fixture issue, not the invariant under test); got %q", func() string {
			if seenByGlobalAdmin == nil {
				return "<cert not found>"
			}
			return seenByGlobalAdmin.PrivateKey
		}())
	}
}
