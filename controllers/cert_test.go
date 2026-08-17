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
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestMaskUnauthorizedCertSecretsForTenantAdmin(t *testing.T) {
	certs := []*object.Cert{
		{Owner: "admin", Name: "cert-built-in", PrivateKey: "global-private-key", AccessSecret: "global-access-secret"},
		{Owner: "niro-alpha", Name: "tenant-cert", PrivateKey: "tenant-private-key", AccessSecret: "tenant-access-secret"},
	}

	got := maskUnauthorizedCertSecrets(certs, false, "niro-alpha")

	if got[0].PrivateKey != "***" {
		t.Fatalf("global privateKey = %q, want masked", got[0].PrivateKey)
	}
	if got[0].AccessSecret != "***" {
		t.Fatalf("global accessSecret = %q, want masked", got[0].AccessSecret)
	}
	if got[1].PrivateKey != "tenant-private-key" {
		t.Fatalf("tenant privateKey = %q, want unmasked", got[1].PrivateKey)
	}
	if got[1].AccessSecret != "tenant-access-secret" {
		t.Fatalf("tenant accessSecret = %q, want unmasked", got[1].AccessSecret)
	}
}

func TestMaskUnauthorizedCertSecretsForTenantAdminDirectGlobalOwner(t *testing.T) {
	certs := []*object.Cert{
		{Owner: "admin", Name: "cert-built-in", PrivateKey: "global-private-key", AccessSecret: "global-access-secret"},
	}

	got := maskUnauthorizedCertSecrets(certs, false, "admin")

	if got[0].PrivateKey != "***" {
		t.Fatalf("global privateKey = %q, want masked", got[0].PrivateKey)
	}
	if got[0].AccessSecret != "***" {
		t.Fatalf("global accessSecret = %q, want masked", got[0].AccessSecret)
	}
}

func TestMaskUnauthorizedCertSecretsForGlobalAdmin(t *testing.T) {
	certs := []*object.Cert{
		{Owner: "admin", Name: "cert-built-in", PrivateKey: "global-private-key", AccessSecret: "global-access-secret"},
	}

	got := maskUnauthorizedCertSecrets(certs, true, "built-in")

	if got[0].PrivateKey != "global-private-key" {
		t.Fatalf("global privateKey = %q, want unmasked", got[0].PrivateKey)
	}
	if got[0].AccessSecret != "global-access-secret" {
		t.Fatalf("global accessSecret = %q, want unmasked", got[0].AccessSecret)
	}
}
