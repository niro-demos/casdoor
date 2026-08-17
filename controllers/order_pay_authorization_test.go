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

func TestEnsureOrderOwnerMatchesUser(t *testing.T) {
	user := &object.User{Owner: "niro-beta", Name: "alice"}

	if err := ensureOrderOwnerMatchesUser("niro-beta", user); err != nil {
		t.Fatalf("same-tenant order placement should be allowed: %v", err)
	}

	if err := ensureOrderOwnerMatchesUser("niro-alpha", user); err == nil {
		t.Fatal("cross-tenant order placement should be forbidden")
	}
}
