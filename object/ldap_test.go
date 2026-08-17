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

package object

import (
	"testing"

	"github.com/casdoor/casdoor/util"
)

// TestLdapCrossOwnerIsolation asserts the tenant-isolation invariant for Ldap
// records: an administrator of one organization must not be able to read or
// modify (hijack, delete) the LDAP server configuration of a different
// organization, even when they supply their own org as the claimed owner
// alongside the victim's real record id.
func TestLdapCrossOwnerIsolation(t *testing.T) {
	InitConfig()

	ownerA := "niro-test-ldap-tenant-a"
	ownerB := "niro-test-ldap-tenant-b"

	ldapA := &Ldap{
		Owner:      ownerA,
		ServerName: "niro-test-ldap-a-" + util.GenerateId(),
		Host:       "internal-ldap.tenant-a.test",
		Port:       389,
		Username:   "cn=tenant-a-binduser,dc=a,dc=test",
		Password:   "TenantASecretPW123",
		BaseDn:     "dc=a,dc=test",
	}
	ok, err := AddLdap(ldapA)
	if err != nil {
		t.Fatalf("failed to seed tenant A's ldap record: %v", err)
	}
	if !ok {
		t.Fatalf("failed to seed tenant A's ldap record: not affected")
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.ID(ldapA.Id).Delete(&Ldap{})
	})

	// Positive control: tenant A can read its own record. This must keep
	// working after the fix -- it proves the fix scopes by owner rather than
	// breaking same-tenant access.
	self, err := GetLdapByOwner(ownerA, ldapA.Id)
	if err != nil {
		t.Fatalf("unexpected error reading tenant A's own record: %v", err)
	}
	if self == nil {
		t.Fatalf("tenant A must be able to read its own ldap record")
	}

	// Invariant: tenant B must not be able to read tenant A's record by
	// claiming its own tenant as owner while keeping tenant A's real record
	// id -- this is the cross-tenant config-read leak.
	leaked, err := GetLdapByOwner(ownerB, ldapA.Id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if leaked != nil {
		t.Fatalf("SECURITY: cross-tenant read succeeded -- tenant B read tenant A's ldap record: %+v", leaked)
	}

	// Invariant: tenant B must not be able to hijack (overwrite) tenant A's
	// record via update-ldap, even by claiming ownership in the request body.
	// isGlobalAdmin=false models a regular tenant admin, as in the finding.
	hijack := &Ldap{
		Id:         ldapA.Id,
		Owner:      ownerB,
		ServerName: "hijacked-by-tenant-b",
		Host:       "attacker-ldap.evil.test",
		Port:       389,
		Username:   "cn=attacker",
		Password:   "attackerpw",
		BaseDn:     "dc=evil",
	}
	affected, err := UpdateLdap(hijack, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if affected {
		t.Fatalf("SECURITY: cross-tenant update succeeded -- tenant B overwrote tenant A's ldap record")
	}

	// Tenant A's record must be untouched by the denied hijack attempt.
	after, err := GetLdapByOwner(ownerA, ldapA.Id)
	if err != nil {
		t.Fatalf("unexpected error re-reading tenant A's record: %v", err)
	}
	if after == nil {
		t.Fatalf("tenant A's record should still exist after the denied hijack attempt")
	}
	if after.Owner != ownerA || after.Host != ldapA.Host || after.Username != ldapA.Username {
		t.Fatalf("tenant A's record was mutated by a denied cross-tenant update: %+v", after)
	}

	// Invariant: tenant B must not be able to delete tenant A's record.
	deleted, err := DeleteLdap(&Ldap{Id: ldapA.Id, Owner: ownerB})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted {
		t.Fatalf("SECURITY: cross-tenant delete succeeded -- tenant B deleted tenant A's ldap record")
	}

	stillThere, err := GetLdapByOwner(ownerA, ldapA.Id)
	if err != nil {
		t.Fatalf("unexpected error re-reading tenant A's record: %v", err)
	}
	if stillThere == nil {
		t.Fatalf("tenant A's record should still exist after tenant B's denied delete attempt")
	}

	// Positive control: tenant A can still update its own record normally.
	selfUpdate := &Ldap{
		Id:         ldapA.Id,
		Owner:      ownerA,
		ServerName: ldapA.ServerName,
		Host:       "internal-ldap.tenant-a.test",
		Port:       390,
		Username:   ldapA.Username,
		Password:   ldapA.Password,
		BaseDn:     ldapA.BaseDn,
	}
	affected, err = UpdateLdap(selfUpdate, false)
	if err != nil {
		t.Fatalf("unexpected error on same-tenant update: %v", err)
	}
	if !affected {
		t.Fatalf("tenant A must be able to update its own ldap record")
	}

	// Positive control: tenant A can still delete its own record normally.
	deleted, err = DeleteLdap(&Ldap{Id: ldapA.Id, Owner: ownerA})
	if err != nil {
		t.Fatalf("unexpected error on same-tenant delete: %v", err)
	}
	if !deleted {
		t.Fatalf("tenant A must be able to delete its own ldap record")
	}
}

// TestLdapGlobalAdminCanReassignOwner asserts the one legitimate cross-tenant
// case: a global admin using the admin console's organization dropdown may
// reassign an Ldap record's owner. This must keep working after the fix.
func TestLdapGlobalAdminCanReassignOwner(t *testing.T) {
	InitConfig()

	ownerA := "niro-test-ldap-tenant-a2"
	ownerC := "niro-test-ldap-tenant-c2"

	ldap := &Ldap{
		Owner:      ownerA,
		ServerName: "niro-test-ldap-reassign-" + util.GenerateId(),
		Host:       "internal-ldap.tenant-a2.test",
		Port:       389,
		Username:   "cn=tenant-a2-binduser,dc=a2,dc=test",
		Password:   "TenantA2SecretPW123",
		BaseDn:     "dc=a2,dc=test",
	}
	ok, err := AddLdap(ldap)
	if err != nil || !ok {
		t.Fatalf("failed to seed ldap record: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.ID(ldap.Id).Delete(&Ldap{})
	})

	reassign := &Ldap{
		Id:         ldap.Id,
		Owner:      ownerC,
		ServerName: ldap.ServerName,
		Host:       ldap.Host,
		Port:       ldap.Port,
		Username:   ldap.Username,
		Password:   ldap.Password,
		BaseDn:     ldap.BaseDn,
	}
	affected, err := UpdateLdap(reassign, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !affected {
		t.Fatalf("a global admin must be able to reassign an ldap record's owner")
	}

	moved, err := GetLdapByOwner(ownerC, ldap.Id)
	if err != nil || moved == nil {
		t.Fatalf("record should now be owned by tenant C: moved=%v err=%v", moved, err)
	}
}
