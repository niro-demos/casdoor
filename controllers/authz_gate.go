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

import "github.com/casdoor/casdoor/object"

// This file centralizes exposure of platform-owned certificate secret material.
//
// object.GetCerts returns platform-owned ("admin"-owned) certs — including the
// shared JWT-signing cert — to any organization (its query is
// `owner = 'admin' OR owner = <caller-org>`). Their private keys must therefore
// be visible only to a true global/site administrator (Owner == "built-in"),
// NOT to any organization-scoped admin. The general-purpose c.IsAdmin()
// predicate OR-s in user.IsAdmin and so returns true for org-scoped admins; the
// correct gate is c.IsGlobalAdmin(). maskCertsForViewer is the single choke
// point the cert-list handlers use so that gate cannot drift between the
// paginated and non-paginated branches, and it is testable in isolation.

// maskCertsForViewer returns the cert list as the viewer is allowed to see it:
// unchanged when the viewer is a global admin, otherwise masked (private keys /
// access secrets replaced with "***"). viewerIsGlobalAdmin must be the caller's
// c.IsGlobalAdmin() result.
func maskCertsForViewer(certs []*object.Cert, viewerIsGlobalAdmin bool) ([]*object.Cert, error) {
	if viewerIsGlobalAdmin {
		return certs, nil
	}
	return object.GetMaskedCerts(certs, nil)
}
