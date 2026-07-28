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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

// newTestLdapApiController builds a minimal, fully wired ApiController for a
// GET request against a given raw URL/query string, mirroring how the real
// production router wires a request into a beego ApiController.
func newTestLdapApiController(rawURL string) *ApiController {
	req := httptest.NewRequest("GET", rawURL, nil)
	w := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(w, req)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "GetLdap", nil)
	return c
}

// TestGetLdapEnforcesRecordOwnerNotUrlPrefix is the regression test for
// TC-C5AF83D7: GET /api/get-ldap resolved the target LDAP server row by its
// bare primary-key id only (object/ldap.go GetLdap(id) never filtered on
// Owner), while routers/authz_filter.go authorized the request using the
// *URL's* owner prefix instead of the resolved row's actual owner. A caller
// could therefore read a foreign organization's LDAP server configuration
// (host, bind DN, base DN) by wrapping the foreign record's bare id in
// their own org's name (e.g. "niro-test/ldap-built-in" instead of the
// record's true "built-in/ldap-built-in").
//
// Invariant under test: GET /api/get-ldap must never return the
// configuration of an LDAP server owned by a different organization than
// the one named in the request's own id prefix, no matter what bare id is
// supplied.
func TestGetLdapEnforcesRecordOwnerNotUrlPrefix(t *testing.T) {
	object.InitConfig()

	callerOrg := "tc-c5af83d7-caller"
	victimOrg := "tc-c5af83d7-victim"

	seedTestLdapOrganization(t, callerOrg)
	seedTestLdapOrganization(t, victimOrg)

	callerLdapId := "tc-c5af83d7-caller-ldap"
	victimLdapId := "tc-c5af83d7-victim-ldap"

	seedTestLdap(t, callerOrg, callerLdapId, "caller-ldap.internal.test")
	seedTestLdap(t, victimOrg, victimLdapId, "victim-ldap.internal.test")

	// --- Positive control: caller reads their OWN ldap via its true id. ---
	legit := newTestLdapApiController("/api/get-ldap?id=" + callerOrg + "/" + callerLdapId)
	legit.GetLdap()
	legitResp, ok := legit.Data["json"].(*Response)
	if !ok || legitResp.Status != "ok" {
		t.Fatalf("baseline broken: caller could not read their own LDAP server: %#v", legit.Data["json"])
	}
	legitLdap, ok := legitResp.Data.(*object.Ldap)
	if !ok || legitLdap == nil || legitLdap.Owner != callerOrg || legitLdap.Host != "caller-ldap.internal.test" {
		t.Fatalf("caller's own ldap read returned unexpected data: %#v", legitResp.Data)
	}

	// --- Exploit: caller relabels the victim's bare id with their own org
	// prefix instead of the record's true owner. ---
	relabeledId := callerOrg + "/" + victimLdapId
	exploit := newTestLdapApiController("/api/get-ldap?id=" + relabeledId)
	exploit.GetLdap()
	exploitResp, ok := exploit.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", exploit.Data["json"])
	}
	if exploitResp.Status == "ok" {
		if ldap, ok := exploitResp.Data.(*object.Ldap); ok && ldap != nil {
			t.Fatalf("VULNERABLE: relabeled id %q resolved to a foreign organization's LDAP server: owner=%s host=%s",
				relabeledId, ldap.Owner, ldap.Host)
		}
	}
}

// TestGetLdapUsersEnforcesRecordOwnerNotUrlPrefix is the regression test for
// the GetLdapUsers() half of TC-C5AF83D7: the same owner-prefix relabeling
// trick let a caller trigger a live LDAP connection attempt using a foreign
// organization's stored bind credentials/host. This asserts the request is
// rejected before any connection is attempted -- the error must be the
// controlled "does not exist" / "Unauthorized operation" response, never a
// dial/connection error that would prove the victim's host was contacted.
func TestGetLdapUsersEnforcesRecordOwnerNotUrlPrefix(t *testing.T) {
	object.InitConfig()

	callerOrg := "tc-c5af83d7-users-caller"
	victimOrg := "tc-c5af83d7-users-victim"

	seedTestLdapOrganization(t, callerOrg)
	seedTestLdapOrganization(t, victimOrg)

	victimLdapId := "tc-c5af83d7-users-victim-ldap"
	// A closed local port: if the buggy code path ever reaches
	// GetLdapConn(), the dial fails immediately ("connection refused")
	// instead of hanging on an unroutable host -- keeping this test fast
	// while still proving whether a connection attempt occurred at all.
	seedTestLdap(t, victimOrg, victimLdapId, "127.0.0.1")

	relabeledId := callerOrg + "/" + victimLdapId
	exploit := newTestLdapApiController("/api/get-ldap-users?id=" + relabeledId)
	exploit.GetLdapUsers()
	exploitResp, ok := exploit.Data["json"].(*Response)
	if !ok {
		t.Fatalf("unexpected response type: %#v", exploit.Data["json"])
	}
	if exploitResp.Status == "ok" {
		t.Fatalf("VULNERABLE: relabeled id %q returned ok status for GetLdapUsers: %#v", relabeledId, exploitResp.Data)
	}
	msg := exploitResp.Msg
	if strings.Contains(msg, "dial") || strings.Contains(msg, "connection refused") || strings.Contains(msg, "127.0.0.1") {
		t.Fatalf("VULNERABLE: request was rejected only after attempting to connect to the foreign LDAP server (leaked host/dial error): %q", msg)
	}
}

func seedTestLdapOrganization(t *testing.T, name string) {
	t.Helper()
	existing, err := object.GetOrganization("admin/" + name)
	if err != nil {
		t.Fatalf("failed to check for existing test organization %s: %v", name, err)
	}
	if existing != nil {
		return
	}

	org := &object.Organization{
		Owner: "admin",
		Name:  name,
	}
	affected, err := object.AddOrganization(org)
	if err != nil || !affected {
		t.Fatalf("failed to seed test organization %s: affected=%v err=%v", name, affected, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteOrganization(org)
	})
}

func seedTestLdap(t *testing.T, owner, id, host string) {
	t.Helper()
	ldap := &object.Ldap{
		Id:         id,
		Owner:      owner,
		ServerName: "tc-c5af83d7-server-" + id,
		Host:       host,
		Port:       389,
		Username:   "cn=" + id + ",dc=example,dc=com",
		Password:   "tc-c5af83d7-pass",
		BaseDn:     "ou=" + id + ",dc=example,dc=com",
	}
	affected, err := object.AddLdap(ldap)
	if err != nil || !affected {
		t.Fatalf("failed to seed test ldap %s/%s: affected=%v err=%v", owner, id, affected, err)
	}
	t.Cleanup(func() {
		_, _ = object.DeleteLdap(ldap)
	})
}
