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

package util

import (
	"strings"
	"testing"
)

// TestCheckForbiddenCharacters is the shared enforcement point for the
// forbidden-character name rule. Every named-object write transport (REST
// add-/update- filter and the MCP tool handlers) routes its name through this
// helper, so this test pins the invariant they all rely on: a name containing
// any of `/?:#&%=+;` is rejected, and a clean name is accepted.
func TestCheckForbiddenCharacters(t *testing.T) {
	// Every character in the forbidden set must be rejected individually — these
	// are the metacharacters that would orphan a record from the owner/name
	// composite-ID lookup.
	for _, ch := range ForbiddenNameChars {
		name := "bad" + string(ch) + "name"
		if err := CheckForbiddenCharacters(name); err == nil {
			t.Errorf("CheckForbiddenCharacters(%q) = nil, want error (contains forbidden char %q)", name, string(ch))
		}
	}

	// The exact shape observed in the finding must be rejected.
	forbidden := []string{
		"bad/name?x=1",
		"bad/app/name",
		"a=b",
		"a;b",
		"a#b",
		"a&b",
		"a%b",
		"a+b",
		"a:b",
	}
	for _, name := range forbidden {
		err := CheckForbiddenCharacters(name)
		if err == nil {
			t.Errorf("CheckForbiddenCharacters(%q) = nil, want error", name)
			continue
		}
		if !strings.Contains(err.Error(), "forbidden characters") {
			t.Errorf("CheckForbiddenCharacters(%q) error = %q, want it to mention \"forbidden characters\"", name, err.Error())
		}
	}

	// Control: legitimate names must be accepted, so a rejection is provably the
	// invariant and not a blanket denial.
	allowed := []string{
		"app-alpha",
		"user_1",
		"my.app",
		"App123",
		"",
	}
	for _, name := range allowed {
		if err := CheckForbiddenCharacters(name); err != nil {
			t.Errorf("CheckForbiddenCharacters(%q) = %v, want nil (legitimate name)", name, err)
		}
	}
}
