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

package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestGlobalAdminOnlyDecisionRejectsOrganizationAdmin(t *testing.T) {
	tests := []struct {
		name string
		user *object.User
		want bool
	}{
		{
			name: "global admin",
			user: &object.User{Owner: "built-in", Name: "admin", IsAdmin: true},
			want: true,
		},
		{
			name: "organization admin",
			user: &object.User{Owner: "acme", Name: "acme-admin", IsAdmin: true},
			want: false,
		},
		{
			name: "organization user",
			user: &object.User{Owner: "acme", Name: "alice", IsAdmin: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGlobalAdminUser(tt.user); got != tt.want {
				t.Fatalf("isGlobalAdminUser() = %v, want %v", got, tt.want)
			}
		})
	}
}
