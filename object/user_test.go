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

// TestGetMaskedUserRedactsCredentialAndTelemetryFieldsForNonPrivilegedCaller
// covers TC-D3DE0191: an anonymous/non-privileged caller (isAdminOrSelf ==
// false) must never receive a user's password salt, password hashing
// algorithm, or creation/login IP history, even though these fields have no
// corresponding organization AccountItem to gate them. A privileged caller
// (isAdminOrSelf == true), such as the user viewing their own profile or an
// admin, must continue to receive them unchanged.
func TestGetMaskedUserRedactsCredentialAndTelemetryFieldsForNonPrivilegedCaller(t *testing.T) {
	sensitiveUser := func() *User {
		return &User{
			Owner:        "niro-alpha",
			Name:         "alice",
			Password:     "casdoor",
			PasswordSalt: "bc93288768d3b640bb0d",
			PasswordType: "bcrypt",
			CreatedIp:    "127.0.0.1",
			LastSigninIp: "127.0.0.1",
		}
	}

	t.Run("non-privileged caller: fields must be redacted", func(t *testing.T) {
		got, err := GetMaskedUser(sensitiveUser(), false)
		if err != nil {
			t.Fatalf("GetMaskedUser() error = %v", err)
		}

		if got.PasswordSalt != "" {
			t.Errorf("PasswordSalt leaked to non-privileged caller: %q", got.PasswordSalt)
		}
		if got.PasswordType != "" {
			t.Errorf("PasswordType leaked to non-privileged caller: %q", got.PasswordType)
		}
		if got.CreatedIp != "" {
			t.Errorf("CreatedIp leaked to non-privileged caller: %q", got.CreatedIp)
		}
		if got.LastSigninIp != "" {
			t.Errorf("LastSigninIp leaked to non-privileged caller: %q", got.LastSigninIp)
		}
	})

	t.Run("control: privileged (admin-or-self) caller keeps the fields", func(t *testing.T) {
		got, err := GetMaskedUser(sensitiveUser(), true)
		if err != nil {
			t.Fatalf("GetMaskedUser() error = %v", err)
		}

		if got.PasswordSalt != "bc93288768d3b640bb0d" {
			t.Errorf("PasswordSalt unexpectedly redacted for privileged caller: %q", got.PasswordSalt)
		}
		if got.PasswordType != "bcrypt" {
			t.Errorf("PasswordType unexpectedly redacted for privileged caller: %q", got.PasswordType)
		}
		if got.CreatedIp != "127.0.0.1" {
			t.Errorf("CreatedIp unexpectedly redacted for privileged caller: %q", got.CreatedIp)
		}
		if got.LastSigninIp != "127.0.0.1" {
			t.Errorf("LastSigninIp unexpectedly redacted for privileged caller: %q", got.LastSigninIp)
		}
	})
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
