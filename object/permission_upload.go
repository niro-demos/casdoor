// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/xlsx"
)

func getPermissionMap(owner string) (map[string]*Permission, error) {
	m := map[string]*Permission{}

	permissions, err := GetPermissions(owner)
	if err != nil {
		return nil, err
	}

	for _, permission := range permissions {
		m[permission.GetId()] = permission
	}

	return m, err
}

func UploadPermissions(owner string, path string) (bool, error) {
	table := xlsx.ReadXlsxFile(path)

	if len(table) == 0 {
		return false, fmt.Errorf("empty table")
	}

	for idx, row := range table[0] {
		splitRow := strings.Split(row, "#")
		if len(splitRow) > 1 {
			table[0][idx] = splitRow[1]
		}
	}

	uploadedPermissions, err := StringArrayToStruct[Permission](table)
	if err != nil {
		return false, err
	}

	uploadedPermissions = scopeUploadedPermissionsToOwner(owner, uploadedPermissions)

	uploadedPermissions = filterInvalidUploadedPermissions(uploadedPermissions)

	oldPermissionMap, err := getPermissionMap(owner)
	if err != nil {
		return false, err
	}

	newPermissions := []*Permission{}
	for _, permission := range uploadedPermissions {
		if _, ok := oldPermissionMap[permission.GetId()]; !ok {
			newPermissions = append(newPermissions, permission)
		}
	}

	if len(newPermissions) == 0 {
		return false, nil
	}

	affected, err := AddPermissionsInBatch(newPermissions)
	if err != nil {
		return false, err
	}

	return affected, nil
}

// scopeUploadedPermissionsToOwner enforces that a bulk permission upload can only
// create records inside the caller's own organization.
//
// The `owner` argument is the caller's enforced session org (derived from the
// session in controllers/permission_upload.go). The parsed rows' Owner and
// subject-reference fields come verbatim from the uploaded spreadsheet and must
// not be trusted: without this, an org-scoped admin could plant a wildcard-Allow
// permission owned by (or granting access to subjects in) any other tenant,
// including the built-in global-admin org.
//
// A global admin (owner == builtInAdminOrg) legitimately manages every org, so
// their explicit per-row owners and subjects are left untouched.
func scopeUploadedPermissionsToOwner(owner string, permissions []*Permission) []*Permission {
	if owner == builtInAdminOrg {
		return permissions
	}

	for _, permission := range permissions {
		if permission == nil {
			continue
		}

		// Ignore whatever the spreadsheet's owner column contained; a non-global
		// admin can only create records in their own org.
		permission.Owner = owner

		// Drop any subject reference that points outside the caller's own org so
		// the upload cannot grant access to (or through) foreign-org subjects.
		permission.Users = filterOwnerScopedRefs(owner, permission.Users)
		permission.Roles = filterOwnerScopedRefs(owner, permission.Roles)
		permission.Groups = filterOwnerScopedRefs(owner, permission.Groups)
	}

	return permissions
}

func filterInvalidUploadedPermissions(permissions []*Permission) []*Permission {
	res := make([]*Permission, 0, len(permissions))
	for _, permission := range permissions {
		if permission == nil {
			continue
		}

		if strings.TrimSpace(permission.Owner) == "" || strings.TrimSpace(permission.Name) == "" {
			continue
		}

		res = append(res, permission)
	}

	return res
}
