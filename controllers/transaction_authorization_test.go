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

func TestScopedTransactionUser(t *testing.T) {
	userName, ok, err := scopedTransactionUser("niro-alpha", "niro-alpha/alice", false)
	if err != nil {
		t.Fatalf("same-tenant transaction scope returned error: %v", err)
	}
	if !ok || userName != "alice" {
		t.Fatalf("same-tenant transaction scope = (%q, %v), want (alice, true)", userName, ok)
	}

	userName, ok, err = scopedTransactionUser("niro-alpha", "niro-beta/alice", false)
	if err != nil {
		t.Fatalf("cross-tenant transaction scope returned parse error: %v", err)
	}
	if ok || userName != "" {
		t.Fatalf("cross-tenant transaction scope = (%q, %v), want forbidden", userName, ok)
	}

	userName, ok, err = scopedTransactionUser("niro-alpha", "niro-beta/admin", true)
	if err != nil {
		t.Fatalf("admin transaction scope returned error: %v", err)
	}
	if !ok || userName != "" {
		t.Fatalf("admin transaction scope = (%q, %v), want unrestricted", userName, ok)
	}
}
