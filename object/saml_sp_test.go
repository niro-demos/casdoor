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
	"strings"
	"testing"
)

func TestGenerateSamlRequestHandlesMissingProvider(t *testing.T) {
	adapter, err := NewAdapter("sqlite", ":memory:", "")
	if err != nil {
		t.Fatalf("failed to initialize test database: %v", err)
	}
	ormer = adapter
	if err := ormer.Engine.Sync2(new(Provider)); err != nil {
		t.Fatalf("failed to initialize provider table: %v", err)
	}

	_, _, err = GenerateSamlRequest("badid", "", "example.com", "en")
	if err == nil {
		t.Fatal("expected malformed provider id to return an error")
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GenerateSamlRequest panicked for a missing provider: %v", r)
		}
	}()

	_, _, err = GenerateSamlRequest("admin/not-a-provider", "", "example.com", "en")
	if err == nil {
		t.Fatal("expected missing provider to return an error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing provider error, got %q", err.Error())
	}
}
