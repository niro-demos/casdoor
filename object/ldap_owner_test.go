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

package object

import (
	"fmt"
	"testing"

	"github.com/casdoor/casdoor/util"
)

// TestLdapForCallerEnforcesOwnerBoundary is the regression test for the
// finding that GetLdap/UpdateLdap/DeleteLdap look records up purely by
// their global random Id, never checking the record's real Owner against
// the caller. That let any org admin read, hijack, or delete another
// organization's LDAP directory server config by supplying their own org
// name alongside the victim's id (e.g. id="acme/<victim-uuid>").
//
// Invariant under test: a non-global-admin caller may only
// read/update/delete an ldap record whose persisted Owner equals their own
// org. A global admin may operate on any org's record.
func TestLdapForCallerEnforcesOwnerBoundary(t *testing.T) {
	InitConfig()

	victimOwner := "niro-test-victim-org-" + util.GenerateId()
	attackerOwner := "niro-test-attacker-org-" + util.GenerateId()

	victim := &Ldap{
		Owner:      victimOwner,
		ServerName: "victim-ldap",
		Host:       "10.0.0.99",
		Port:       389,
		Username:   "cn=admin,dc=victim",
		Password:   "victimSecretPW",
		BaseDn:     "dc=victim,dc=com",
	}
	if ok, err := AddLdap(victim); err != nil || !ok {
		t.Fatalf("setup: AddLdap failed: ok=%v err=%v", ok, err)
	}
	defer func() {
		_, _ = DeleteLdap(&Ldap{Id: victim.Id})
	}()

	// --- positive control: the legitimate owner can read its own record.
	// Isolates the assertions below from a broken environment/DB. ---
	self, err := GetLdapForCaller(victim.Id, false, victimOwner)
	if err != nil {
		t.Fatalf("positive control: GetLdapForCaller returned error: %v", err)
	}
	if self == nil || self.Id != victim.Id || self.Owner != victimOwner {
		t.Fatalf("positive control failed: owner could not read its own ldap record (env unhealthy): %+v", self)
	}

	// --- READ: an org admin from a different org must not be able to
	// fetch the victim's record by id alone. ---
	leaked, err := GetLdapForCaller(victim.Id, false, attackerOwner)
	if err != nil {
		t.Fatalf("GetLdapForCaller returned error: %v", err)
	}
	if leaked != nil {
		t.Fatalf("RED (invariant violated): org admin of %q was able to read org %q's ldap record (id=%s): host=%q username=%q baseDn=%q",
			attackerOwner, victimOwner, victim.Id, leaked.Host, leaked.Username, leaked.BaseDn)
	}

	// --- UPDATE (hijack): an org admin from a different org must not be
	// able to mutate the victim's record, including reassigning its Owner
	// to their own org. ---
	hijack := &Ldap{
		Id:         victim.Id,
		Owner:      attackerOwner,
		ServerName: "pwned-by-attacker",
		Host:       "attacker.evil.example",
		Port:       389,
		Username:   "cn=attacker",
		Password:   "newpw123",
		BaseDn:     "dc=evil,dc=com",
	}
	if affected, err := UpdateLdapForCaller(hijack, false, attackerOwner); err != nil {
		t.Fatalf("UpdateLdapForCaller returned error: %v", err)
	} else if affected {
		after, _ := GetLdap(victim.Id)
		t.Fatalf("RED (invariant violated): org admin of %q was able to hijack org %q's ldap record (id=%s): owner now %q, host now %q",
			attackerOwner, victimOwner, victim.Id, after.Owner, after.Host)
	}
	if after, _ := GetLdap(victim.Id); after == nil || after.Owner != victimOwner || after.Host != "10.0.0.99" {
		t.Fatalf("victim record was mutated despite a denied update: %+v", after)
	}

	// --- DELETE: an org admin from a different org must not be able to
	// delete the victim's record. ---
	if affected, err := DeleteLdapForCaller(victim.Id, false, attackerOwner); err != nil {
		t.Fatalf("DeleteLdapForCaller returned error: %v", err)
	} else if affected {
		t.Fatalf("RED (invariant violated): org admin of %q was able to delete org %q's ldap record (id=%s)",
			attackerOwner, victimOwner, victim.Id)
	}
	if after, _ := GetLdap(victim.Id); after == nil {
		t.Fatalf("victim record was deleted despite a denied delete")
	}

	// --- global admin retains full access regardless of owner. ---
	if admin, err := GetLdapForCaller(victim.Id, true, attackerOwner); err != nil || admin == nil {
		t.Fatalf("global admin must still be able to read any org's ldap record: %+v, err=%v", admin, err)
	}

	fmt.Println("GREEN: invariant held - org admin could not read, hijack, or delete another org's ldap record")
}
