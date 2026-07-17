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
	"os"
	"path/filepath"
	"testing"
)

// TestUploadUsersMalformedFileDoesNotPanic reproduces TC-E76748DA: an org
// admin submitting a non-xlsx (plain CSV) file to the bulk-user-import
// endpoint must not crash the server via an unrecovered panic from the
// underlying xlsx parser. UploadUsers must instead return a clean error
// before touching any organization/user data.
func TestUploadUsersMalformedFileDoesNotPanic(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "malformed.xlsx")
	content := "name,displayName,email\ncsvuser1,CSV User,csvuser1@acme.example.com\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UploadUsers panicked on a malformed (non-xlsx) upload instead of returning a clean error: %v", r)
		}
	}()

	userObj := &User{Owner: "acme", Name: "acme-admin"}
	affected, err := UploadUsers("acme", tmpFile, userObj, "en")
	if err == nil {
		t.Fatalf("expected UploadUsers to return an error for a malformed upload, got affected=%v, err=nil", affected)
	}
}
