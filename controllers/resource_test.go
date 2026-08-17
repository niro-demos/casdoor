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

import (
	"os"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestCanUploadResourceForTarget(t *testing.T) {
	tests := []struct {
		name           string
		actor          *object.User
		targetOwner    string
		targetUsername string
		want           bool
	}{
		{
			name:           "reject standard user targeting another organization",
			actor:          &object.User{Owner: "niro-alpha", Name: "alice"},
			targetOwner:    "niro-beta",
			targetUsername: "alice",
			want:           false,
		},
		{
			name:           "allow standard user targeting self",
			actor:          &object.User{Owner: "niro-alpha", Name: "alice"},
			targetOwner:    "niro-alpha",
			targetUsername: "alice",
			want:           true,
		},
		{
			name:           "reject standard user targeting peer in same organization",
			actor:          &object.User{Owner: "niro-alpha", Name: "alice"},
			targetOwner:    "niro-alpha",
			targetUsername: "bob",
			want:           false,
		},
		{
			name:           "allow organization admin targeting peer in same organization",
			actor:          &object.User{Owner: "niro-alpha", Name: "admin", IsAdmin: true},
			targetOwner:    "niro-alpha",
			targetUsername: "alice",
			want:           true,
		},
		{
			name:           "reject organization admin targeting another organization",
			actor:          &object.User{Owner: "niro-alpha", Name: "admin", IsAdmin: true},
			targetOwner:    "niro-beta",
			targetUsername: "alice",
			want:           false,
		},
		{
			name:           "allow global admin targeting another organization",
			actor:          &object.User{Owner: "built-in", Name: "admin"},
			targetOwner:    "niro-beta",
			targetUsername: "alice",
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canUploadResourceForTarget(tt.actor, tt.targetOwner, tt.targetUsername); got != tt.want {
				t.Fatalf("canUploadResourceForTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUploadResourceAuthorizesBeforeStorageWork(t *testing.T) {
	source, err := os.ReadFile("resource.go")
	if err != nil {
		t.Fatal(err)
	}

	body := string(source)
	start := strings.Index(body, "func (c *ApiController) UploadResource()")
	end := strings.Index(body, "func canUploadResourceForTarget")
	if start == -1 || end == -1 || end <= start {
		t.Fatal("UploadResource body was not found")
	}
	body = body[start:end]
	authIndex := strings.Index(body, "RequireSignedInUser()")
	fileIndex := strings.Index(body, `GetFile("file")`)
	providerIndex := strings.Index(body, `GetProviderFromContext("Storage")`)
	uploadIndex := strings.Index(body, "UploadFileSafe(")

	if authIndex == -1 {
		t.Fatal("UploadResource does not require a signed-in user")
	}
	if fileIndex == -1 || providerIndex == -1 || uploadIndex == -1 {
		t.Fatal("UploadResource storage path markers were not found")
	}
	if authIndex > fileIndex || authIndex > providerIndex || authIndex > uploadIndex {
		t.Fatal("UploadResource must authorize the signed-in actor before reading the file, resolving storage, or uploading")
	}
}
