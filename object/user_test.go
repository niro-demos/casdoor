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

// TestGetMaskedUserRedactsPasswordHashMetadataForNonAdminNonSelf is the
// regression test for TC-B8339174: GetFilteredUser only strips fields that
// have a matching AccountItems entry, so passwordSalt, passwordType,
// createdIp, signinWrongTimes, and lastSigninWrongTime (which have no
// AccountItems entry) pass straight through to a public-profile GET
// /api/get-user response -- to an unauthenticated caller, and to any
// non-admin/non-self caller in general. GetMaskedUser must unconditionally
// blank these fields for any non-admin/non-self caller, the same way
// password/originalToken/originalRefreshToken already are, so no admin
// AccountItems misconfiguration can leak them.
func TestGetMaskedUserRedactsPasswordHashMetadataForNonAdminNonSelf(t *testing.T) {
	newSensitiveUser := func() *User {
		return &User{
			Owner:               "acme",
			Name:                "alice",
			Password:            "casdoor",
			PasswordSalt:        "test-fixture-salt-0123456789ab",
			PasswordType:        "bcrypt",
			CreatedIp:           "127.0.0.1",
			SigninWrongTimes:    5,
			LastSigninWrongTime: "2026-07-17T01:55:43Z",
		}
	}

	t.Run("non-admin, non-self caller must not see password-hash metadata or login-failure telemetry", func(t *testing.T) {
		got, err := GetMaskedUser(newSensitiveUser(), false)
		if err != nil {
			t.Fatalf("GetMaskedUser() error = %v", err)
		}

		// Positive control: the already-masked field stays masked, proving the
		// function ran and isn't a no-op.
		if got.Password != "***" {
			t.Errorf("control failed: Password = %q, want masked \"***\" -- masking pipeline itself is broken", got.Password)
		}

		if got.PasswordSalt != "" {
			t.Errorf("invariant violated: PasswordSalt leaked to non-admin/non-self caller: %q", got.PasswordSalt)
		}
		if got.PasswordType != "" {
			t.Errorf("invariant violated: PasswordType leaked to non-admin/non-self caller: %q", got.PasswordType)
		}
		if got.CreatedIp != "" {
			t.Errorf("invariant violated: CreatedIp leaked to non-admin/non-self caller: %q", got.CreatedIp)
		}
		if got.SigninWrongTimes != 0 {
			t.Errorf("invariant violated: SigninWrongTimes leaked to non-admin/non-self caller: %v", got.SigninWrongTimes)
		}
		if got.LastSigninWrongTime != "" {
			t.Errorf("invariant violated: LastSigninWrongTime leaked to non-admin/non-self caller: %q", got.LastSigninWrongTime)
		}
	})

	t.Run("admin-or-self caller still sees password-hash metadata and login-failure telemetry", func(t *testing.T) {
		// Control: the same fields must NOT be stripped for an admin or the
		// user herself, since they legitimately need this data (e.g. to know
		// which hash algorithm a stored password uses, or to see their own
		// lockout state) -- proving the fix is scoped to non-admin/non-self,
		// not a blanket removal of the fields.
		got, err := GetMaskedUser(newSensitiveUser(), true)
		if err != nil {
			t.Fatalf("GetMaskedUser() error = %v", err)
		}

		if got.PasswordSalt == "" || got.PasswordType == "" || got.CreatedIp == "" || got.LastSigninWrongTime == "" {
			t.Errorf("admin/self caller unexpectedly had password-hash metadata stripped: %+v", got)
		}
	})
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
