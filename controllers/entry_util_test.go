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
	"net/http"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// TC-B8325909: OTLP ingestion must authorize on a real per-provider credential,
// not on request metadata a caller controls. otlpTokenFromRequest is the
// credential-extraction step; it must read the token only from the dedicated
// auth headers (Authorization: Bearer / X-OpenClaw-Token) and must never treat
// spoofable identity headers (e.g. X-Forwarded-For) as a credential.
func TestOtlpTokenFromRequest(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "bearer token",
			headers: map[string]string{"Authorization": "Bearer s3cr3t-token"},
			want:    "s3cr3t-token",
		},
		{
			name:    "bearer is case-insensitive scheme",
			headers: map[string]string{"Authorization": "bearer s3cr3t-token"},
			want:    "s3cr3t-token",
		},
		{
			name:    "custom header",
			headers: map[string]string{"X-OpenClaw-Token": "s3cr3t-token"},
			want:    "s3cr3t-token",
		},
		{
			name:    "no credential header yields empty token",
			headers: map[string]string{},
			want:    "",
		},
		{
			// A forged source-IP header is not a credential and must never be
			// interpreted as one.
			name:    "forged X-Forwarded-For is not a credential",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.201"},
			want:    "",
		},
		{
			name:    "non-bearer authorization is ignored",
			headers: map[string]string{"Authorization": "Basic dXNlcjpwYXNz"},
			want:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "http://example/api/v1/traces", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			ctx := &context.Context{Request: req}

			if got := otlpTokenFromRequest(ctx); got != tc.want {
				t.Fatalf("otlpTokenFromRequest() = %q, want %q (headers=%v)", got, tc.want, tc.headers)
			}
		})
	}
}
