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

func TestCanReadSubscription(t *testing.T) {
	subscription := &object.Subscription{
		Owner: "organization",
		Name:  "subscription",
		User:  "alice",
	}

	tests := []struct {
		name          string
		isGlobalAdmin bool
		user          *object.User
		want          bool
	}{
		{name: "anonymous caller", want: false},
		{name: "non-owner", user: &object.User{Owner: "organization", Name: "bob"}, want: false},
		{name: "administrator from another organization", user: &object.User{Owner: "other-organization", Name: "admin", IsAdmin: true}, want: false},
		{name: "owner", user: &object.User{Owner: "organization", Name: "alice"}, want: true},
		{name: "organization administrator", user: &object.User{Owner: "organization", Name: "admin", IsAdmin: true}, want: true},
		{name: "global administrator", isGlobalAdmin: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canReadSubscription(tt.isGlobalAdmin, tt.user, subscription); got != tt.want {
				t.Fatalf("canReadSubscription() = %t, want %t", got, tt.want)
			}
		})
	}
}
