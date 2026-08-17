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

import "testing"

func TestCanReadUserOrders(t *testing.T) {
	tests := []struct {
		name          string
		owner         string
		user          string
		sessionUser   string
		isGlobalAdmin bool
		isAdmin       bool
		want          bool
	}{
		{
			name:        "user reads own orders",
			owner:       "niro-alpha",
			user:        "alice",
			sessionUser: "niro-alpha/alice",
			want:        true,
		},
		{
			name:        "same-tenant admin reads tenant user orders",
			owner:       "niro-alpha",
			user:        "alice",
			sessionUser: "niro-alpha/admin",
			isAdmin:     true,
			want:        true,
		},
		{
			name:        "tenant admin cannot read another tenant",
			owner:       "niro-alpha",
			user:        "alice",
			sessionUser: "niro-beta/admin",
			isAdmin:     true,
			want:        false,
		},
		{
			name:          "global admin can read any tenant",
			owner:         "niro-alpha",
			user:          "alice",
			sessionUser:   "built-in/admin",
			isGlobalAdmin: true,
			isAdmin:       true,
			want:          true,
		},
		{
			name:        "same-tenant non-admin cannot read another user",
			owner:       "niro-alpha",
			user:        "alice",
			sessionUser: "niro-alpha/bob",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canReadUserOrders(tt.owner, tt.user, tt.sessionUser, tt.isGlobalAdmin, tt.isAdmin); got != tt.want {
				t.Fatalf("canReadUserOrders() = %v, want %v", got, tt.want)
			}
		})
	}
}
