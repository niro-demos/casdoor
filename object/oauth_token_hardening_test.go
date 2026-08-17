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
	"sync"
	"testing"
	"time"
)

func TestConfidentialClientSecretRequiredForPasswordAndRefreshGrants(t *testing.T) {
	application := &Application{
		Owner:        "admin",
		Name:         "confidential-app",
		ClientId:     "client-id",
		ClientSecret: "registered-secret",
	}

	tests := []struct {
		name         string
		grantType    string
		clientSecret string
		wantErr      bool
	}{
		{name: "password grant rejects wrong secret", grantType: "password", clientSecret: "wrong", wantErr: true},
		{name: "refresh grant rejects omitted secret", grantType: "refresh_token", clientSecret: "", wantErr: true},
		{name: "refresh grant rejects wrong secret", grantType: "refresh_token", clientSecret: "wrong", wantErr: true},
		{name: "correct secret accepted", grantType: "password", clientSecret: "registered-secret", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenError := validateOAuthClientSecret(application, tt.grantType, tt.clientSecret)
			if tt.wantErr {
				if tokenError == nil || tokenError.Error != InvalidClient {
					t.Fatalf("validateOAuthClientSecret() = %#v, want invalid_client", tokenError)
				}
				return
			}
			if tokenError != nil {
				t.Fatalf("validateOAuthClientSecret() = %#v, want nil", tokenError)
			}
		})
	}
}

func TestPublicOAuthClientMayOmitSecret(t *testing.T) {
	application := &Application{
		Owner:    "admin",
		Name:     "public-app",
		ClientId: "public-client",
	}

	if tokenError := validateOAuthClientSecret(application, "refresh_token", ""); tokenError != nil {
		t.Fatalf("public client omitted secret returned %#v, want nil", tokenError)
	}
}

func TestIntrospectionRequiresTokenIssuedToAuthenticatedClient(t *testing.T) {
	authenticated := &Application{
		Owner:    "admin",
		Name:     "app-beta",
		ClientId: "beta-client",
	}
	issuing := &Application{
		Owner:    "admin",
		Name:     "app-alpha",
		ClientId: "alpha-client",
	}
	token := &Token{
		Owner:       issuing.Owner,
		Application: issuing.Name,
	}

	if isTokenIssuedToClient(authenticated, token) {
		t.Fatal("cross-client introspection was allowed; want inactive result")
	}
	if !isTokenIssuedToClient(issuing, token) {
		t.Fatal("issuing client was rejected; want active result")
	}
}

func TestDeviceCodeClaimIsSingleUseUnderConcurrency(t *testing.T) {
	store := &memoryDeviceAuthStore{}
	deviceCode := "approved-device-code"
	store.Store(deviceCode, DeviceAuthCache{
		UserSignIn:    true,
		UserName:      "alice",
		ApplicationId: "admin/app-alpha",
		ClientId:      "alpha-client",
		Scope:         "openid profile",
		RequestAt:     time.Now(),
		Status:        DeviceAuthStatusApproved,
	})

	const workers = 32
	start := make(chan struct{})
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, tokenError := claimDeviceAuthForTokenIssue(store, deviceCode, "alpha-client", time.Now())
			results <- tokenError == nil
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful device-code claims = %d, want exactly 1", successes)
	}
}
