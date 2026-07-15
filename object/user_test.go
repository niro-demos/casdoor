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

func TestGetMaskedUserMasksPasswordSalt(t *testing.T) {
	// Regression test for TC-7DA53EE0: GetMaskedUser() masked Password to
	// "***" for non-admin, non-self viewers, but left PasswordSalt --
	// real server-side password-verification material (see
	// object/check.go's CheckPassword / credManager.IsPasswordCorrect) --
	// untouched. GetFilteredUser() only zeroes fields that have a matching
	// accountItems entry, and no org config maps an accountItems name to
	// the PasswordSalt field, so the salt was returned in full to any org
	// member who could view another member's profile at all, even when
	// the org's "Password" accountItem viewRule is "Self".
	user := &User{Owner: "acme", Name: "bob", Password: "casbin", PasswordSalt: "84dcc35d0bce4f2c028e"}

	got, err := GetMaskedUser(user, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "***" {
		t.Errorf("GetMaskedUser(isAdminOrSelf=false): Password = %q, want masked", got.Password)
	}
	if got.PasswordSalt != "***" {
		t.Errorf("GetMaskedUser(isAdminOrSelf=false): PasswordSalt = %q, want masked -- a non-admin, non-self viewer must not receive another user's raw password salt", got.PasswordSalt)
	}
}

func TestGetMaskedUserKeepsOwnPasswordSaltForSelf(t *testing.T) {
	// Positive control: a user viewing their own profile (or an admin)
	// must still be able to see the passwordSalt -- the Self/Admin
	// viewRule path must keep working, isolating the bug above to the
	// non-admin, non-self case rather than breaking self-view entirely.
	user := &User{Owner: "acme", Name: "bob", Password: "casbin", PasswordSalt: "84dcc35d0bce4f2c028e"}

	got, err := GetMaskedUser(user, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordSalt != "84dcc35d0bce4f2c028e" {
		t.Errorf("GetMaskedUser(isAdminOrSelf=true): PasswordSalt = %q, want unmasked original value", got.PasswordSalt)
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
