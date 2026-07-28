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

package controllers

import "testing"

// TestIsUploadFileTypeBlocked asserts the invariant behind TC-535DF2D7:
// UploadResource must refuse to persist a file whose extension or declared
// content type a browser would execute as script/markup if the static
// "/files" handler ever served it back on Casdoor's own cookied origin
// (stored XSS via unrestricted resource upload). A benign, non-executable
// upload must keep working exactly as before, and the one legitimate
// exception -- an admin uploading an application's "termsOfUse" HTML page --
// must keep working too.
func TestIsUploadFileTypeBlocked(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		contentType string
		tag         string
		isAdmin     bool
		wantBlocked bool
	}{
		{
			name:        "html file with html content-type from a standard user must be blocked",
			filename:    "vector-xss-test-1.html",
			contentType: "text/html",
			tag:         "custom",
			isAdmin:     false,
			wantBlocked: true,
		},
		{
			name:        "html file uploaded by an admin without the termsOfUse tag must still be blocked",
			filename:    "vector-xss-test-1.html",
			contentType: "text/html",
			tag:         "custom",
			isAdmin:     true,
			wantBlocked: true,
		},
		{
			name:        "htm extension must be blocked regardless of declared content-type",
			filename:    "vector.htm",
			contentType: "application/octet-stream",
			tag:         "custom",
			isAdmin:     false,
			wantBlocked: true,
		},
		{
			name:        "svg file must be blocked (script-capable image format)",
			filename:    "vector.svg",
			contentType: "image/svg+xml",
			tag:         "custom",
			isAdmin:     false,
			wantBlocked: true,
		},
		{
			name:        "js file must be blocked even when declared as a generic content-type",
			filename:    "vector.js",
			contentType: "application/octet-stream",
			tag:         "custom",
			isAdmin:     false,
			wantBlocked: true,
		},
		{
			name:        "png image must not be blocked (positive control)",
			filename:    "avatar.png",
			contentType: "image/png",
			tag:         "avatar",
			isAdmin:     false,
			wantBlocked: false,
		},
		{
			name:        "plain text file must not be blocked (positive control)",
			filename:    "notes.txt",
			contentType: "text/plain",
			tag:         "custom",
			isAdmin:     false,
			wantBlocked: false,
		},
		{
			name:        "admin uploading termsOfUse HTML for an application must be allowed",
			filename:    "app-niro-test.html",
			contentType: "text/html",
			tag:         "termsOfUse",
			isAdmin:     true,
			wantBlocked: false,
		},
		{
			name:        "a standard (non-admin) user cannot use the termsOfUse tag to smuggle html",
			filename:    "app-niro-test.html",
			contentType: "text/html",
			tag:         "termsOfUse",
			isAdmin:     false,
			wantBlocked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUploadFileTypeBlocked(tt.filename, tt.contentType, tt.tag, tt.isAdmin)
			if got != tt.wantBlocked {
				t.Errorf("isUploadFileTypeBlocked(%q, %q, %q, %v) = %v, want %v",
					tt.filename, tt.contentType, tt.tag, tt.isAdmin, got, tt.wantBlocked)
			}
		})
	}
}
