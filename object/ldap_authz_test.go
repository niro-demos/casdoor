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

package object

import (
	"testing"

	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/names"
	_ "modernc.org/sqlite" // in-memory sqlite driver for hermetic tests
)

// setupLdapTestOrmer stands up a hermetic, in-memory sqlite database and points
// the package-level `ormer` at it so the object-layer LDAP functions
// (GetLdap*/UpdateLdap/DeleteLdap) run against a real engine without a live DB
// or config. It seeds two tenants' LDAP records so cross-tenant behaviour can be
// asserted, and restores the previous ormer on cleanup.
//
// This mirrors the harness scenario used by the PoCs (an org-alpha admin acting
// on an org-beta LDAP record) but in the project's native test suite: the seeded
// values from credentials.yaml don't exist here, so equivalent tenants/records
// are recreated with the object-layer factories.
func setupLdapTestOrmer(t *testing.T) (alpha *Ldap, beta *Ldap) {
	t.Helper()

	engine, err := xorm.NewEngine("sqlite", "file:ldap_authz_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}
	// Column names in Casdoor are snake_case (e.g. server_name); match the
	// production mapper so Cols()/Where() clauses resolve to real columns.
	engine.SetTableMapper(names.SnakeMapper{})
	if err = engine.Sync2(new(Ldap)); err != nil {
		t.Fatalf("failed to sync Ldap table: %v", err)
	}

	prev := ormer
	ormer = &Ormer{Engine: engine}
	t.Cleanup(func() {
		_ = engine.Close()
		ormer = prev
	})

	alpha = &Ldap{
		Id: "alpha-uuid-1111", Owner: "org-alpha", CreatedTime: "2026-01-01",
		ServerName: "alpha-ldap", Host: "ldap.alpha.internal", Port: 389,
		Username: "cn=admin,dc=alpha", Password: "alphaSecretPW", BaseDn: "dc=alpha,dc=internal",
	}
	beta = &Ldap{
		Id: "beta-uuid-2222", Owner: "org-beta", CreatedTime: "2026-01-01",
		ServerName: "beta-ldap", Host: "ldap.beta.internal", Port: 389,
		Username: "cn=admin,dc=beta", Password: "betaSecretPW", BaseDn: "dc=beta,dc=internal",
	}
	if _, err = AddLdap(alpha); err != nil {
		t.Fatalf("seed alpha ldap: %v", err)
	}
	if _, err = AddLdap(beta); err != nil {
		t.Fatalf("seed beta ldap: %v", err)
	}
	return alpha, beta
}

func mustGetRawLdap(t *testing.T, id string) *Ldap {
	t.Helper()
	l := Ldap{Id: id}
	existed, err := ormer.Engine.Get(&l)
	if err != nil {
		t.Fatalf("raw get %s: %v", id, err)
	}
	if !existed {
		return nil
	}
	return &l
}

// TestGetLdapByOwnerRejectsCrossOrg covers TC-53BC7730: a caller asserting its
// own org (org-alpha) must not be able to resolve another org's (org-beta) LDAP
// record — host, bind DN, base DN, and stored bind password — by supplying the
// victim's UUID under its own org prefix.
//
// Invariant: an org admin must not read another organization's LDAP config or
// bind credentials by owner-prefix spoofing.
func TestGetLdapByOwnerRejectsCrossOrg(t *testing.T) {
	alpha, beta := setupLdapTestOrmer(t)

	// Positive control: the legitimate owner CAN read its own record, proving the
	// resolver works and the reject below is the invariant, not a broken setup.
	own, err := GetLdapByOwner("org-alpha", alpha.Id)
	if err != nil {
		t.Fatalf("control: owner reading own record errored: %v", err)
	}
	if own == nil || own.Id != alpha.Id || own.Host != "ldap.alpha.internal" {
		t.Fatalf("control: owner could not read its own LDAP record, got %+v", own)
	}

	// Attack: org-alpha admin swaps only the owner prefix, keeping org-beta's UUID.
	// The victim's config/credentials must NOT be returned.
	leaked, err := GetLdapByOwner("org-alpha", beta.Id)
	if err != nil {
		t.Fatalf("cross-org read errored unexpectedly: %v", err)
	}
	if leaked != nil {
		t.Fatalf("INVARIANT VIOLATED (TC-53BC7730): org-alpha admin read org-beta's LDAP record "+
			"via owner-prefix spoofing: owner=%q host=%q bindDN=%q baseDn=%q password=%q",
			leaked.Owner, leaked.Host, leaked.Username, leaked.BaseDn, leaked.Password)
	}
}

// TestUpdateLdapRejectsCrossOrg covers the update half of TC-3E14AD63: an
// org-alpha admin must not be able to retarget org-beta's LDAP integration by
// naming org-beta's UUID while spoofing the body owner to org-alpha.
//
// Invariant: an org admin must not modify or retarget another org's LDAP record.
func TestUpdateLdapRejectsCrossOrg(t *testing.T) {
	alpha, beta := setupLdapTestOrmer(t)

	// Positive control: org-alpha admin CAN update its own record.
	alpha.Host = "ldap.alpha.updated"
	ok, err := UpdateLdap(alpha)
	if err != nil {
		t.Fatalf("control: owner updating own record errored: %v", err)
	}
	if !ok {
		t.Fatalf("control: owner could not update its own LDAP record")
	}
	if got := mustGetRawLdap(t, alpha.Id); got == nil || got.Host != "ldap.alpha.updated" {
		t.Fatalf("control: own update did not persist, got %+v", got)
	}

	// Attack: name org-beta's UUID, spoof the owner to org-alpha, and retarget the
	// host at an attacker-controlled endpoint.
	spoof := &Ldap{
		Id: beta.Id, Owner: "org-alpha", ServerName: "beta-HIJACKED",
		Host: "attacker-exfil.example.com", Port: 389,
		Username: "cn=admin,dc=beta", Password: "hijackedPW", BaseDn: "dc=beta,dc=internal",
	}
	_, _ = UpdateLdap(spoof)

	// The stored org-beta record must be untouched: same owner, same host.
	after := mustGetRawLdap(t, beta.Id)
	if after == nil {
		t.Fatalf("org-beta record disappeared after cross-org update")
	}
	if after.Owner != "org-beta" || after.Host != "ldap.beta.internal" {
		t.Fatalf("INVARIANT VIOLATED (TC-3E14AD63): org-alpha admin retargeted org-beta's LDAP record: "+
			"owner=%q host=%q (expected owner=org-beta host=ldap.beta.internal)",
			after.Owner, after.Host)
	}
}

// TestDeleteLdapRejectsCrossOrg covers the delete half of TC-3E14AD63: an
// org-alpha admin must not be able to delete org-beta's LDAP integration.
//
// Invariant: an org admin must not delete another org's LDAP record.
func TestDeleteLdapRejectsCrossOrg(t *testing.T) {
	alpha, beta := setupLdapTestOrmer(t)

	// Attack: delete org-beta's record from an org-alpha session (spoofed owner).
	spoof := &Ldap{Id: beta.Id, Owner: "org-alpha"}
	_, _ = DeleteLdap(spoof)

	if got := mustGetRawLdap(t, beta.Id); got == nil {
		t.Fatalf("INVARIANT VIOLATED (TC-3E14AD63): org-alpha admin DELETED org-beta's LDAP record")
	}

	// Positive control: the true owner CAN delete its own record.
	ok, err := DeleteLdap(&Ldap{Id: alpha.Id, Owner: "org-alpha"})
	if err != nil {
		t.Fatalf("control: owner deleting own record errored: %v", err)
	}
	if !ok {
		t.Fatalf("control: owner could not delete its own LDAP record")
	}
	if got := mustGetRawLdap(t, alpha.Id); got != nil {
		t.Fatalf("control: own delete did not remove the record")
	}
}
