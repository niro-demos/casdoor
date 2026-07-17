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

//go:build !skipCi

package xlsx

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadSheet is a positive control: a real xlsx file must still parse
// cleanly. Paired with TestReadXlsxFileMalformedInputDoesNotPanic below, it
// proves a malformed-input failure is an isolated defect, not a broken
// environment.
func TestReadSheet(t *testing.T) {
	table, err := ReadXlsxFile("user_test.xlsx")
	if err != nil {
		t.Fatalf("expected a valid xlsx fixture to parse without error, got: %v", err)
	}
	if len(table) == 0 {
		t.Fatalf("expected a valid xlsx fixture to yield at least one row")
	}
}

// TestReadXlsxFileMalformedInputDoesNotPanic reproduces TC-E76748DA at the
// parser level: a malformed (non-zip) "xlsx" file must not panic the
// process. It must instead be reported as a normal error so callers (e.g.
// object.UploadUsers -> controllers.UploadUsers) can return a clean 4xx/5xx
// JSON error instead of an unrecovered panic reaching beego's debug error
// handler.
func TestReadXlsxFileMalformedInputDoesNotPanic(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "malformed.xlsx")
	content := "name,displayName,email\ncsvuser1,CSV User,csvuser1@acme.example.com\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ReadXlsxFile panicked on malformed (non-zip) input instead of returning a clean error: %v", r)
		}
	}()

	table, err := ReadXlsxFile(tmpFile)
	if err == nil {
		t.Fatalf("expected ReadXlsxFile to return an error for malformed input, got table=%v, err=nil", table)
	}
}
