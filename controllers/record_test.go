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

import "testing"

func TestRecordOrganizationScope(t *testing.T) {
	tests := []struct {
		name                  string
		callerOrganization    string
		isGlobalAdmin         bool
		requestedOrganization string
		want                  string
	}{
		{
			name:               "organization admin is scoped to own tenant",
			callerOrganization: "tenant-a",
			want:               "tenant-a",
		},
		{
			name:                  "organization admin cannot override tenant",
			callerOrganization:    "tenant-a",
			requestedOrganization: "tenant-b",
			want:                  "tenant-a",
		},
		{
			name:                  "global admin can select tenant",
			callerOrganization:    "built-in",
			isGlobalAdmin:         true,
			requestedOrganization: "tenant-b",
			want:                  "tenant-b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRecordOrganization(tt.callerOrganization, tt.isGlobalAdmin, tt.requestedOrganization); got != tt.want {
				t.Fatalf("record query organization = %q, want %q", got, tt.want)
			}
		})
	}
}
