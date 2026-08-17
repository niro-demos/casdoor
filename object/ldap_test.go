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
	"fmt"
	"testing"
	"time"
)

func setupLdapTestDb(t *testing.T) {
	t.Helper()

	adapter, err := NewAdapter("sqlite3", fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), "")
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}
	t.Cleanup(adapter.close)

	ormer = adapter
	if err := ormer.Engine.Sync2(new(Ldap)); err != nil {
		t.Fatalf("Sync2(Ldap) error = %v", err)
	}
}

func TestUpdateLdapRejectsOwnerMismatch(t *testing.T) {
	setupLdapTestDb(t)

	ldap := newTestLdap("tc-update-owner-mismatch", "alpha", "original")
	if ok, err := AddLdap(ldap); err != nil || !ok {
		t.Fatalf("AddLdap() = %v, %v; want true, nil", ok, err)
	}

	spoofed := *ldap
	spoofed.Owner = "beta"
	spoofed.ServerName = "taken-over"
	spoofed.Host = "changed.invalid"

	affected, err := UpdateLdap(&spoofed)
	if err != nil {
		t.Fatalf("UpdateLdap() error = %v", err)
	}
	if affected {
		t.Fatalf("UpdateLdap() affected cross-tenant record with spoofed owner")
	}

	got, err := GetLdap(ldap.Id)
	if err != nil {
		t.Fatalf("GetLdap() error = %v", err)
	}
	if got == nil {
		t.Fatalf("GetLdap() = nil, want persisted LDAP")
	}
	if got.Owner != "alpha" || got.ServerName != "original" || got.Host != ldap.Host {
		t.Fatalf("LDAP changed after owner-mismatched update: owner=%q serverName=%q host=%q", got.Owner, got.ServerName, got.Host)
	}

	legitimate := *ldap
	legitimate.ServerName = "alpha-updated"
	legitimate.Host = "alpha-updated.invalid"
	affected, err = UpdateLdap(&legitimate)
	if err != nil || !affected {
		t.Fatalf("legitimate UpdateLdap() = %v, %v; want true, nil", affected, err)
	}
	got, err = GetLdap(ldap.Id)
	if err != nil {
		t.Fatalf("GetLdap() after legitimate update error = %v", err)
	}
	if got.Owner != "alpha" || got.ServerName != legitimate.ServerName || got.Host != legitimate.Host {
		t.Fatalf("legitimate update not preserved: owner=%q serverName=%q host=%q", got.Owner, got.ServerName, got.Host)
	}
}

func TestDeleteLdapRejectsOwnerMismatch(t *testing.T) {
	setupLdapTestDb(t)

	ldap := newTestLdap("tc-delete-owner-mismatch", "alpha", "delete-original")
	if ok, err := AddLdap(ldap); err != nil || !ok {
		t.Fatalf("AddLdap() = %v, %v; want true, nil", ok, err)
	}

	affected, err := DeleteLdap(&Ldap{Id: ldap.Id, Owner: "beta"})
	if err != nil {
		t.Fatalf("DeleteLdap() error = %v", err)
	}
	if affected {
		t.Fatalf("DeleteLdap() affected cross-tenant record with spoofed owner")
	}

	got, err := GetLdap(ldap.Id)
	if err != nil {
		t.Fatalf("GetLdap() error = %v", err)
	}
	if got == nil || got.Owner != "alpha" {
		t.Fatalf("LDAP missing or changed after owner-mismatched delete: %#v", got)
	}

	affected, err = DeleteLdap(&Ldap{Id: ldap.Id, Owner: "alpha"})
	if err != nil || !affected {
		t.Fatalf("legitimate DeleteLdap() = %v, %v; want true, nil", affected, err)
	}
	got, err = GetLdap(ldap.Id)
	if err != nil {
		t.Fatalf("GetLdap() after legitimate delete error = %v", err)
	}
	if got != nil {
		t.Fatalf("GetLdap() after legitimate delete = %#v, want nil", got)
	}
}

func newTestLdap(id string, owner string, serverName string) *Ldap {
	return &Ldap{
		Id:                  id,
		Owner:               owner,
		CreatedTime:         time.Now().UTC().Format(time.RFC3339),
		ServerName:          serverName,
		Host:                id + ".invalid",
		Port:                636,
		EnableSsl:           true,
		AllowSelfSignedCert: false,
		Username:            "cn=admin",
		Password:            "ldap-password",
		BaseDn:              "dc=example,dc=invalid",
		Filter:              "(cn=*)",
		FilterFields:        []string{},
		DefaultGroup:        "",
		DefaultGroups:       []string{},
		PasswordType:        "plain",
		CustomAttributes:    map[string]string{},
	}
}
