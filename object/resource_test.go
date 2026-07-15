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
	"fmt"
	"testing"
	"time"

	"github.com/casdoor/casdoor/util"
)

func resourceNamePresent(resources []*Resource, name string) bool {
	for _, r := range resources {
		if r.Name == name {
			return true
		}
	}
	return false
}

// TestGetResourcesOwnerBuiltInDoesNotLeakOtherOwners is a regression test for
// TC-A113ABC1. GetResources (and GetPaginationResources below) used to
// special-case owner=="built-in" the same as owner=="" and drop the owner
// filter entirely:
//
//	if owner == "built-in" || owner == "" {
//		owner = ""
//		user = ""
//	}
//
// That meant a request scoped to owner=="built-in" silently returned every
// resource row in the database, from every organization, not just built-in's
// own. owner=="" is a legitimate "no filter" convention used elsewhere in
// this codebase (see object.GetUsers), but "built-in" is a real, distinct
// organization name and must filter like any other owner value.
func TestGetResourcesOwnerBuiltInDoesNotLeakOtherOwners(t *testing.T) {
	InitConfig()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	otherOwner := "niro-regress-tenant-" + suffix
	builtInResourceName := "niro-regress-built-in-" + suffix
	otherResourceName := "niro-regress-other-" + suffix

	builtInResource := &Resource{
		Owner:       "built-in",
		Name:        builtInResourceName,
		CreatedTime: util.GetCurrentTime(),
		User:        "admin",
		FileName:    builtInResourceName + ".txt",
		FileType:    "text",
		FileFormat:  "txt",
		Url:         "http://internal.example.com/" + builtInResourceName + ".txt",
		Description: "niro-regress TC-A113ABC1: built-in-owned control resource",
	}
	otherResource := &Resource{
		Owner:       otherOwner,
		Name:        otherResourceName,
		CreatedTime: util.GetCurrentTime(),
		User:        "someone-else",
		FileName:    otherResourceName + ".txt",
		FileType:    "text",
		FileFormat:  "txt",
		Url:         "http://internal.example.com/" + otherResourceName + ".txt",
		Description: "niro-regress TC-A113ABC1: unrelated-tenant resource that must not leak",
	}

	if _, err := AddResource(builtInResource); err != nil {
		t.Fatalf("harness problem: could not create built-in resource fixture: %v", err)
	}
	defer DeleteResource(builtInResource)

	if _, err := AddResource(otherResource); err != nil {
		t.Fatalf("harness problem: could not create other-tenant resource fixture: %v", err)
	}
	defer DeleteResource(otherResource)

	t.Run("GetResources", func(t *testing.T) {
		resources, err := GetResources("built-in", "")
		if err != nil {
			t.Fatalf("GetResources(built-in, \"\") returned an error: %v", err)
		}

		if resourceNamePresent(resources, otherResourceName) {
			t.Fatalf("invariant violated: GetResources(owner=\"built-in\") returned resource %q owned by unrelated tenant %q — the owner filter collapsed", otherResourceName, otherOwner)
		}
		if !resourceNamePresent(resources, builtInResourceName) {
			t.Fatalf("harness problem: GetResources(owner=\"built-in\") did not return the built-in-owned control resource %q — cannot trust the isolation check above", builtInResourceName)
		}
	})

	t.Run("GetPaginationResources", func(t *testing.T) {
		resources, err := GetPaginationResources("built-in", "", 0, 10, "", "", "", "")
		if err != nil {
			t.Fatalf("GetPaginationResources(built-in, \"\") returned an error: %v", err)
		}

		if resourceNamePresent(resources, otherResourceName) {
			t.Fatalf("invariant violated: GetPaginationResources(owner=\"built-in\") returned resource %q owned by unrelated tenant %q — the owner filter collapsed", otherResourceName, otherOwner)
		}
		if !resourceNamePresent(resources, builtInResourceName) {
			t.Fatalf("harness problem: GetPaginationResources(owner=\"built-in\") did not return the built-in-owned control resource %q — cannot trust the isolation check above", builtInResourceName)
		}
	})
}
