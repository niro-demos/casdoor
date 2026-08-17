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

// TestGetMaskedUserRedactsPasswordSaltAndType is a regression test for
// TC-4D7608B4: GetMaskedUser() must strip PasswordSalt/PasswordType for any
// caller that is not the record's owner/admin, the same way it already
// strips Password itself. These fields are credential-cracking-support
// metadata (bcrypt salt + hash algorithm) and must never reach an
// unauthorized viewer, independent of any organization-level
// AccountItems/IsProfilePublic configuration (that gate is handled
// separately by GetFilteredUser and is out of scope here).
func TestGetMaskedUserRedactsPasswordSaltAndType(t *testing.T) {
	// Unauthorized viewer (not admin, not self): salt/type must be redacted,
	// exactly like Password already is.
	unauthorizedUser := &User{Password: "casdoor", PasswordSalt: "a0a3c851707b5ea401ee", PasswordType: "bcrypt"}
	got, err := GetMaskedUser(unauthorizedUser, false)
	if err != nil {
		t.Fatalf("GetMaskedUser() unexpected error: %v", err)
	}
	if got.PasswordSalt != "" {
		t.Errorf("GetMaskedUser() for unauthorized viewer: PasswordSalt = %q, want redacted (empty)", got.PasswordSalt)
	}
	if got.PasswordType != "" {
		t.Errorf("GetMaskedUser() for unauthorized viewer: PasswordType = %q, want redacted (empty)", got.PasswordType)
	}
	if got.Password != "***" {
		t.Errorf("GetMaskedUser() for unauthorized viewer: Password = %q, want %q", got.Password, "***")
	}

	// Control: the record owner/admin must still see their own salt/type —
	// this fix must not take that away.
	selfUser := &User{Password: "casdoor", PasswordSalt: "a0a3c851707b5ea401ee", PasswordType: "bcrypt"}
	got, err = GetMaskedUser(selfUser, true)
	if err != nil {
		t.Fatalf("GetMaskedUser() unexpected error: %v", err)
	}
	if got.PasswordSalt != "a0a3c851707b5ea401ee" {
		t.Errorf("GetMaskedUser() for admin/self: PasswordSalt = %q, want unchanged", got.PasswordSalt)
	}
	if got.PasswordType != "bcrypt" {
		t.Errorf("GetMaskedUser() for admin/self: PasswordType = %q, want unchanged", got.PasswordType)
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
