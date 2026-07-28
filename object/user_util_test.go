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

import (
	"testing"
)

// TestUserVisibleFailsClosedWhenAccountItemMissing is the regression test for
// TC-9DF8B356: a standard (non-admin) user must not be able to write a
// permission-gated account field (e.g. "Is admin") via /api/update-user just
// because the organization's accountItems list happens to have no entry for
// that field.
//
// userVisible(isAdmin, item) is the sole permission gate CheckPermissionForUpdateUser
// consults before accepting any field change (see the "Is admin" check at
// user_util.go around line 878: `if !userVisible(isAdmin, item) { revert }`).
// When GetAccountItemByName finds no configured AccountItem for the field, it
// returns a nil item, and userVisible must treat that the same as the most
// restrictive configured item (view/modify locked to admins), not the most
// permissive one.
func TestUserVisibleFailsClosedWhenAccountItemMissing(t *testing.T) {
	// RED case (the vulnerability): no AccountItem is configured for the
	// field (item == nil), and the caller is a standard, non-admin user.
	// A fail-closed implementation must deny the write.
	if got := userVisible(false, nil); got {
		t.Errorf("userVisible(isAdmin=false, item=nil) = true, want false: "+
			"a standard user must not be treated as permitted to write a field "+
			"the organization never configured an AccountItem for (self-promotion path for TC-9DF8B356)")
	}

	// Control: an admin (global or org admin) must still be able to write a
	// field with no configured AccountItem - the fix must not lock admins
	// out of managing undeclared fields.
	if got := userVisible(true, nil); !got {
		t.Errorf("userVisible(isAdmin=true, item=nil) = false, want true: "+
			"an admin must still be able to write a field with no configured AccountItem")
	}
}

// TestUserVisiblePreservesExistingBehaviorForConfiguredItems locks in the
// pre-existing behavior of userVisible for the case an AccountItem *is*
// configured, so the fix for the nil-item case does not regress it.
func TestUserVisiblePreservesExistingBehaviorForConfiguredItems(t *testing.T) {
	tests := []struct {
		name    string
		isAdmin bool
		item    *AccountItem
		want    bool
	}{
		{
			name:    "admin-only field, standard user, denied",
			isAdmin: false,
			item:    &AccountItem{Name: "Is admin", ViewRule: "Admin", ModifyRule: "Admin"},
			want:    false,
		},
		{
			name:    "admin-only field, admin user, allowed",
			isAdmin: true,
			item:    &AccountItem{Name: "Is admin", ViewRule: "Admin", ModifyRule: "Admin"},
			want:    true,
		},
		{
			name:    "open field, standard user, allowed",
			isAdmin: false,
			item:    &AccountItem{Name: "Display name", ViewRule: "", ModifyRule: "Self"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := userVisible(tt.isAdmin, tt.item); got != tt.want {
				t.Errorf("userVisible(%v, %+v) = %v, want %v", tt.isAdmin, tt.item, got, tt.want)
			}
		})
	}
}
