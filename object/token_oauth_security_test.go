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

import "testing"

func TestAuthorizationCodeRedirectMustMatchIssuedRedirect(t *testing.T) {
	token := &Token{RedirectUri: "http://localhost:8000/callback"}

	tests := []struct {
		name        string
		redirectURI string
		want        bool
	}{
		{"exact redirect", "http://localhost:8000/callback", true},
		{"different allowed redirect", "http://localhost:8000/other", false},
		{"lookalike redirect", "http://localhost:8000/callback.attacker.test/collect", false},
		{"missing redirect", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authorizationCodeRedirectMatches(token, tt.redirectURI); got != tt.want {
				t.Fatalf("authorizationCodeRedirectMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}
