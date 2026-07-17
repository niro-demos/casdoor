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
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

func updateUserColumn(column string, user *User) bool {
	affected, err := ormer.Engine.ID(core.PK{user.Owner, user.Name}).Cols(column).Update(user)
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func TestFaceIdUsesLowerCamelImageUrlJsonField(t *testing.T) {
	var faceId FaceId
	err := json.Unmarshal([]byte(`{"name":"face","imageUrl":"http://example.com/face.jpg","faceIdData":[]}`), &faceId)
	if err != nil {
		t.Fatal(err)
	}

	if faceId.ImageUrl != "http://example.com/face.jpg" {
		t.Fatalf("ImageUrl = %q, want %q", faceId.ImageUrl, "http://example.com/face.jpg")
	}

	data, err := json.Marshal(faceId)
	if err != nil {
		t.Fatal(err)
	}

	var fields map[string]interface{}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}

	if _, ok := fields["imageUrl"]; !ok {
		t.Fatalf("marshaled FaceId does not contain imageUrl: %s", string(data))
	}
	if _, ok := fields["ImageUrl"]; ok {
		t.Fatalf("marshaled FaceId unexpectedly contains ImageUrl: %s", string(data))
	}
}

func TestSyncAvatarsFromGitHub(t *testing.T) {
	InitConfig()

	users, _ := GetGlobalUsers()
	for _, user := range users {
		if user.GitHub == "" {
			continue
		}

		user.Avatar = fmt.Sprintf("https://avatars.githubusercontent.com/%s", user.GitHub)
		updateUserColumn("avatar", user)
	}
}

func TestSyncIds(t *testing.T) {
	InitConfig()

	users, _ := GetGlobalUsers()
	for _, user := range users {
		if user.Id != "" {
			continue
		}

		user.Id = util.GenerateId()
		updateUserColumn("id", user)
	}
}

func TestSyncHashes(t *testing.T) {
	InitConfig()

	users, _ := GetGlobalUsers()
	for _, user := range users {
		if user.Hash != "" {
			continue
		}

		err := user.UpdateUserHash()
		if err != nil {
			panic(err)
		}
		updateUserColumn("hash", user)
	}
}

func TestGetMaskedUsers(t *testing.T) {
	type args struct {
		users []*User
	}
	tests := []struct {
		name string
		args args
		want []*User
	}{
		{
			name: "1",
			args: args{users: []*User{{Password: "casdoor"}, {Password: "casbin"}}},
			want: []*User{{Password: "***"}, {Password: "***"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GetMaskedUsers(tt.args.users); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetMaskedUsers() = %v, want %v", got, tt.want)
			}
		})
	}
}

// acmeAccountItems mirrors the account-item configuration used by the
// finding: "Password" and "3rd-party logins" are Self-only, "Is admin" and
// "IP whitelist" are Admin-only, "Balance" is Self-only.
func acmeAccountItems() []*AccountItem {
	return []*AccountItem{
		{Name: "Password", ViewRule: "Self"},
		{Name: "3rd-party logins", ViewRule: "Self"},
		{Name: "Is admin", ViewRule: "Admin"},
		{Name: "IP whitelist", ViewRule: "Admin"},
		{Name: "Balance", ViewRule: "Self"},
	}
}

// TC-B308AF2C / TC-85B4A556: GetFilteredUser() polices Self/Admin
// accountItems by lower-casing accountItem.Name and looking up a struct
// field of the *same* name via reflection. That 1:1 name match works for
// "Password" -> User.Password, "Is admin" -> User.IsAdmin, "IP whitelist"
// -> User.IpWhitelist, "Balance" -> User.Balance, but it silently skips the
// "Password" accountItem's sibling fields User.PasswordSalt/User.PasswordType,
// and "3rd-party logins" doesn't match any single field at all (the ~80
// individual OAuth provider fields have unrelated names) -- so those fields
// pass through unfiltered for any non-Self/non-Admin viewer, whether that
// viewer is an anonymous caller in a public-profile org (TC-B308AF2C) or an
// authenticated, non-admin, same-org peer (TC-85B4A556) -- both reach this
// function with isAdmin=false, isAdminOrSelf=false.
func TestGetFilteredUserStripsPasswordMetadataAndThirdPartyLoginsForNonSelfNonAdmin(t *testing.T) {
	user := &User{
		Owner:        "acme",
		Name:         "bob",
		Password:     "casbin",
		PasswordSalt: "f197bda79c2364ee8688",
		PasswordType: "bcrypt",
		IsAdmin:      true,
		IpWhitelist:  "203.0.113.9/32",
		Balance:      12345,
		GitHub:       "niro-github-secret-link",
		Google:       "niro-google-secret-link",
	}

	got, err := GetFilteredUser(user, false, false, acmeAccountItems())
	if err != nil {
		t.Fatal(err)
	}

	// Positive control: the exact-name-match fields are already correctly
	// filtered on master -- if these fail, the test (or environment) is
	// broken, not just the fields under test.
	if got.IsAdmin != false {
		t.Errorf("GetFilteredUser(): IsAdmin = %v, want false (Admin viewRule)", got.IsAdmin)
	}
	if got.IpWhitelist != "" {
		t.Errorf("GetFilteredUser(): IpWhitelist = %q, want empty (Admin viewRule)", got.IpWhitelist)
	}
	if got.Balance != 0 {
		t.Errorf("GetFilteredUser(): Balance = %v, want 0 (Self viewRule)", got.Balance)
	}
	if got.Password != "" {
		t.Errorf("GetFilteredUser(): Password = %q, want empty (Self viewRule)", got.Password)
	}

	// The violation under test: PasswordSalt/PasswordType (sibling fields of
	// the "Password" accountItem) and GitHub/Google (covered by the
	// "3rd-party logins" accountItem) must be stripped for a caller who is
	// neither the user nor an admin -- exactly like Password itself.
	if got.PasswordSalt != "" {
		t.Errorf("GetFilteredUser(): PasswordSalt = %q, want empty -- a non-self, non-admin viewer must not receive password-hash metadata", got.PasswordSalt)
	}
	if got.PasswordType != "" {
		t.Errorf("GetFilteredUser(): PasswordType = %q, want empty -- a non-self, non-admin viewer must not receive password-hash metadata", got.PasswordType)
	}
	if got.GitHub != "" {
		t.Errorf("GetFilteredUser(): GitHub = %q, want empty -- a non-self, non-admin viewer must not receive third-party-login bindings", got.GitHub)
	}
	if got.Google != "" {
		t.Errorf("GetFilteredUser(): Google = %q, want empty -- a non-self, non-admin viewer must not receive third-party-login bindings", got.Google)
	}
}

// Positive control isolating the fix to the non-self/non-admin case: a user
// viewing their own profile, and an admin, must still see the full record --
// "Self"/"Admin" viewRule fields must not be stripped for those callers.
func TestGetFilteredUserKeepsPasswordMetadataForSelfAndAdmin(t *testing.T) {
	base := &User{
		Owner:        "acme",
		Name:         "bob",
		Password:     "casbin",
		PasswordSalt: "f197bda79c2364ee8688",
		PasswordType: "bcrypt",
		GitHub:       "niro-github-secret-link",
		Google:       "niro-google-secret-link",
	}

	for _, tt := range []struct {
		name          string
		isAdmin       bool
		isAdminOrSelf bool
	}{
		{name: "self", isAdmin: false, isAdminOrSelf: true},
		{name: "admin", isAdmin: true, isAdminOrSelf: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			user := *base
			got, err := GetFilteredUser(&user, tt.isAdmin, tt.isAdminOrSelf, acmeAccountItems())
			if err != nil {
				t.Fatal(err)
			}
			if got.PasswordSalt != "f197bda79c2364ee8688" {
				t.Errorf("GetFilteredUser(isAdminOrSelf=true): PasswordSalt = %q, want unmasked original value", got.PasswordSalt)
			}
			if got.PasswordType != "bcrypt" {
				t.Errorf("GetFilteredUser(isAdminOrSelf=true): PasswordType = %q, want unmasked original value", got.PasswordType)
			}
			if got.GitHub != "niro-github-secret-link" {
				t.Errorf("GetFilteredUser(isAdminOrSelf=true): GitHub = %q, want unmasked original value", got.GitHub)
			}
			if got.Google != "niro-google-secret-link" {
				t.Errorf("GetFilteredUser(isAdminOrSelf=true): Google = %q, want unmasked original value", got.Google)
			}
		})
	}
}

func TestGetUserByField(t *testing.T) {
	InitConfig()

	user, _ := GetUserByField("built-in", "DingTalk", "test")
	if user != nil {
		t.Logf("%+v", user)
	} else {
		t.Log("no user found")
	}
}

func TestGetEmailsForUsers(t *testing.T) {
	InitConfig()

	emailMap := map[string]int{}
	emails := []string{}
	users, _ := GetUsers("built-in")
	for _, user := range users {
		if user.Email == "" {
			continue
		}

		if _, ok := emailMap[user.Email]; !ok {
			emailMap[user.Email] = 1
			emails = append(emails, user.Email)
		}
	}

	text := strings.Join(emails, "\n")
	println(text)
}
