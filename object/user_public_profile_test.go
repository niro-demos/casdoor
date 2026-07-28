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

import "testing"

func TestGetMaskedUserRemovesInternalFieldsForPublicProfile(t *testing.T) {
	user := &User{
		Owner:          "built-in",
		Name:           "alice",
		Email:          "alice@example.test",
		Phone:          "15555550101",
		Affiliation:    "Engineering",
		Password:       "secret",
		PasswordSalt:   "salt-value",
		PasswordType:   "bcrypt",
		CreatedIp:      "127.0.0.1",
		RegisterSource: "app-built-in",
	}

	masked, err := GetMaskedUser(user, false)
	if err != nil {
		t.Fatal(err)
	}

	if masked.Password != "***" {
		t.Fatalf("Password = %q, want masked", masked.Password)
	}
	if masked.PasswordSalt != "" || masked.PasswordType != "" || masked.CreatedIp != "" || masked.RegisterSource != "" {
		t.Fatalf("public masked user exposes internal fields: passwordSalt=%q passwordType=%q createdIp=%q registerSource=%q",
			masked.PasswordSalt, masked.PasswordType, masked.CreatedIp, masked.RegisterSource)
	}
}
