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

func UpdateLdap(ldap *Ldap) (bool, error) {
	var l *Ldap
	var err error
	if l, err = GetLdap(ldap.Id); err != nil {
		return false, nil
	} else if l == nil {
		return false, nil
	}

	if ldap.Password == "***" {
		ldap.Password = l.Password
	}

	affected, err := ormer.Engine.ID(ldap.Id).Cols("owner", "server_name", "host",
		"port", "enable_ssl", "username", "password", "base_dn", "filter", "filter_fields", "auto_sync", "default_group", "default_groups", "password_type", "allow_self_signed_cert", "custom_attributes", "enable_groups").Update(ldap)
	if err != nil {
		return false, nil
	}

	return affected != 0, nil
}

func DeleteLdap(ldap *Ldap) (bool, error) {
	affected, err := ormer.Engine.ID(ldap.Id).Delete(&Ldap{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

// GetLdapForCaller fetches the ldap record identified by id and, unless the
// caller is a global admin, verifies the record's persisted Owner matches
// callerOwner before returning it.
//
// GetLdap looks records up purely by their global random Id with no notion
// of tenancy, so this check must never trust an owner value the caller
// supplied (e.g. the "acme" prefix in a spoofed id="acme/<victim-uuid>")
// — only the row's own Owner, as stored in the database, counts. A mismatch
// is reported the same way as "not found" (nil, nil) so a caller cannot use
// this endpoint to distinguish "doesn't exist" from "isn't yours".
func GetLdapForCaller(id string, isGlobalAdmin bool, callerOwner string) (*Ldap, error) {
	ldap, err := GetLdap(id)
	if err != nil || ldap == nil {
		return ldap, err
	}

	if !isGlobalAdmin && ldap.Owner != callerOwner {
		return nil, nil
	}

	return ldap, nil
}

// UpdateLdapForCaller updates the ldap record identified by ldap.Id, after
// verifying (via GetLdapForCaller) that the caller is authorized to mutate
// it. Non-global-admins additionally cannot use the update to move the
// record to a different organization: their supplied Owner is ignored in
// favor of the record's existing Owner.
func UpdateLdapForCaller(ldap *Ldap, isGlobalAdmin bool, callerOwner string) (bool, error) {
	prev, err := GetLdapForCaller(ldap.Id, isGlobalAdmin, callerOwner)
	if err != nil || prev == nil {
		return false, err
	}

	if !isGlobalAdmin {
		ldap.Owner = prev.Owner
	}

	return UpdateLdap(ldap)
}

// DeleteLdapForCaller deletes the ldap record identified by id, after
// verifying (via GetLdapForCaller) that the caller is authorized to delete
// it.
func DeleteLdapForCaller(id string, isGlobalAdmin bool, callerOwner string) (bool, error) {
	prev, err := GetLdapForCaller(id, isGlobalAdmin, callerOwner)
	if err != nil || prev == nil {
		return false, err
	}

	return DeleteLdap(&Ldap{Id: id})
}
