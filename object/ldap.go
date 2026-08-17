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
	"github.com/casdoor/casdoor/util"
)

type Ldap struct {
	Id          string `xorm:"varchar(100) notnull pk" json:"id"`
	Owner       string `xorm:"varchar(100)" json:"owner"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	ServerName          string            `xorm:"varchar(100)" json:"serverName"`
	Host                string            `xorm:"varchar(100)" json:"host"`
	Port                int               `xorm:"int" json:"port"`
	EnableSsl           bool              `xorm:"bool" json:"enableSsl"`
	AllowSelfSignedCert bool              `xorm:"bool" json:"allowSelfSignedCert"`
	Username            string            `xorm:"varchar(100)" json:"username"`
	Password            string            `xorm:"varchar(100)" json:"password"`
	BaseDn              string            `xorm:"varchar(500)" json:"baseDn"`
	Filter              string            `xorm:"varchar(200)" json:"filter"`
	FilterFields        []string          `xorm:"varchar(100)" json:"filterFields"`
	DefaultGroup        string            `xorm:"varchar(100)" json:"defaultGroup"`
	DefaultGroups       []string          `xorm:"mediumtext" json:"defaultGroups"`
	PasswordType        string            `xorm:"varchar(100)" json:"passwordType"`
	CustomAttributes    map[string]string `json:"customAttributes"`

	AutoSync     int    `json:"autoSync"`
	LastSync     string `xorm:"varchar(100)" json:"lastSync"`
	EnableGroups bool   `xorm:"bool" json:"enableGroups"`
}

func AddLdap(ldap *Ldap) (bool, error) {
	if len(ldap.Id) == 0 {
		ldap.Id = util.GenerateId()
	}

	if len(ldap.CreatedTime) == 0 {
		ldap.CreatedTime = util.GetCurrentTime()
	}

	affected, err := ormer.Engine.Insert(ldap)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func CheckLdapExist(ldap *Ldap) (bool, error) {
	var result []*Ldap
	err := ormer.Engine.Find(&result, &Ldap{
		Owner:    ldap.Owner,
		Host:     ldap.Host,
		Port:     ldap.Port,
		Username: ldap.Username,
		Password: ldap.Password,
		BaseDn:   ldap.BaseDn,
	})
	if err != nil {
		return false, err
	}

	if len(result) > 0 {
		return true, nil
	}

	return false, nil
}

func GetLdaps(owner string) ([]*Ldap, error) {
	var ldaps []*Ldap
	err := ormer.Engine.Desc("created_time").Find(&ldaps, &Ldap{Owner: owner})
	if err != nil {
		return ldaps, err
	}

	return ldaps, nil
}

func GetLdap(id string) (*Ldap, error) {
	if util.IsStringsEmpty(id) {
		return nil, nil
	}

	ldap := Ldap{Id: id}
	existed, err := ormer.Engine.Get(&ldap)
	if err != nil {
		return &ldap, nil
	}

	if existed {
		return &ldap, nil
	} else {
		return nil, nil
	}
}

// GetLdapByOwner looks up an Ldap record by its global id and returns it only
// if the record's real Owner matches owner. This is the tenant-isolation
// boundary for Ldap: unlike GetLdap, it never returns a record belonging to a
// different organization, regardless of what owner segment the caller claims.
func GetLdapByOwner(owner, id string) (*Ldap, error) {
	ldap, err := GetLdap(id)
	if err != nil {
		return nil, err
	}

	if ldap == nil || ldap.Owner != owner {
		return nil, nil
	}

	return ldap, nil
}

func GetMaskedLdap(ldap *Ldap, errs ...error) (*Ldap, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	if ldap == nil {
		return nil, nil
	}

	if ldap.Password != "" {
		ldap.Password = "***"
	}

	return ldap, nil
}

func GetMaskedLdaps(ldaps []*Ldap, errs ...error) ([]*Ldap, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	var err error
	for _, ldap := range ldaps {
		ldap, err = GetMaskedLdap(ldap)
		if err != nil {
			return nil, err
		}
	}
	return ldaps, nil
}

// UpdateLdap updates an existing Ldap record. Unless isGlobalAdmin is true,
// the caller may only update a record it actually owns: ldap.Owner (the
// caller-claimed owner) must match the record's real, current Owner, and the
// write itself is scoped to that real owner so a forged owner segment/body
// can never touch another organization's record. isGlobalAdmin allows the
// one legitimate cross-tenant case: a global admin reassigning a record's
// owner via the admin console.
func UpdateLdap(ldap *Ldap, isGlobalAdmin bool) (bool, error) {
	var l *Ldap
	var err error
	if isGlobalAdmin {
		l, err = GetLdap(ldap.Id)
	} else {
		l, err = GetLdapByOwner(ldap.Owner, ldap.Id)
	}
	if err != nil {
		return false, err
	} else if l == nil {
		return false, nil
	}

	if ldap.Password == "***" {
		ldap.Password = l.Password
	}

	affected, err := ormer.Engine.ID(ldap.Id).Where("owner = ?", l.Owner).Cols("owner", "server_name", "host",
		"port", "enable_ssl", "username", "password", "base_dn", "filter", "filter_fields", "auto_sync", "default_group", "default_groups", "password_type", "allow_self_signed_cert", "custom_attributes", "enable_groups").Update(ldap)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

// DeleteLdap deletes an Ldap record. The caller may only delete a record it
// actually owns: ldap.Owner (the caller-claimed owner) must match the
// record's real, current Owner, and the delete itself is scoped to that real
// owner so a forged owner segment/body can never remove another
// organization's record.
func DeleteLdap(ldap *Ldap) (bool, error) {
	l, err := GetLdapByOwner(ldap.Owner, ldap.Id)
	if err != nil {
		return false, err
	} else if l == nil {
		return false, nil
	}

	affected, err := ormer.Engine.ID(ldap.Id).Where("owner = ?", l.Owner).Delete(&Ldap{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}
