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
	"net/http/httptest"
	"strings"
	"testing"

	beecontext "github.com/beego/beego/v2/server/web/context"
)

func TestUploadResourceRequiresAuthenticationBeforeReadingFile(t *testing.T) {
	tests := []struct {
		name          string
		currentUserID string
		username      string
		wantLoginErr  bool
	}{
		{name: "anonymous upload is rejected", username: "test", wantLoginErr: true},
		{name: "signed-in admin upload reaches request validation", currentUserID: "app/test", username: "Built-in-Untracked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/api/upload-resource?owner=built-in&user="+tt.username+"&application=app-built-in", nil)
			recorder := httptest.NewRecorder()
			ctx := beecontext.NewContext()
			ctx.Reset(recorder, request)
			ctx.Input.SetData("currentUserId", tt.currentUserID)

			controller := &ApiController{}
			controller.Init(ctx, "ApiController", "UploadResource", nil)
			controller.UploadResource()

			gotLoginErr := strings.Contains(recorder.Body.String(), "Please login first")
			if gotLoginErr != tt.wantLoginErr {
				t.Fatalf("response = %q, login error = %t, want %t", recorder.Body.String(), gotLoginErr, tt.wantLoginErr)
			}
		})
	}
}
