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
	"testing"

	"github.com/casdoor/casdoor/util"
)

// forbiddenCasAttributeNames are internal account-security / bookkeeping
// fields that must never be exposed to a CAS relying party via
// <cas:userAttributes>, regardless of what gets added to the User struct
// in the future.
var forbiddenCasAttributeNames = []string{
	"passwordSalt",
	"passwordType",
	"createdIp",
	"registerSource",
	"id",
	"signinWrongTimes",
	"balance",
	"karma",
	"isForbidden",
}

// TestGenerateCasTokenOnlyExposesIdentityAttributes asserts the invariant
// that a CAS serviceValidate response's <cas:userAttributes> block only
// contains identity attributes needed by relying parties (name, email,
// phone, displayName, ...), never password hashing metadata or internal
// account bookkeeping fields such as passwordSalt, passwordType, createdIp,
// registerSource, or the internal record id.
func TestGenerateCasTokenOnlyExposesIdentityAttributes(t *testing.T) {
	InitConfig()

	owner := "cas-token-test-org"
	name := "cas-token-test-user"

	testUser := &User{
		Owner:            owner,
		Name:             name,
		CreatedTime:      util.GetCurrentTime(),
		Id:               "internal-id-should-not-leak",
		Password:         "supersecretpassword",
		PasswordSalt:     "supersecretsalt",
		PasswordType:     "bcrypt",
		CreatedIp:        "203.0.113.7",
		RegisterSource:   "built-in/admin",
		SigninWrongTimes: 3,
		Balance:          205,
		Karma:            17,
		IsForbidden:      false,
		Email:            "cas-token-test-user@example.com",
		DisplayName:      "CAS Token Test User",
		Phone:            "+10000000000",
		FirstName:        "Cas",
		LastName:         "Tester",
		Affiliation:      "Acme Corp",
	}

	// Start from a clean slate and clean up after ourselves; this test owns
	// this owner/name pair exclusively.
	_, _ = ormer.Engine.Delete(&User{Owner: owner, Name: name})
	defer func() {
		_, _ = ormer.Engine.Delete(&User{Owner: owner, Name: name})
	}()

	if _, err := ormer.Engine.Insert(testUser); err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	ticket, err := GenerateCasToken(testUser.GetId(), "http://example.com/callback")
	if err != nil {
		t.Fatalf("GenerateCasToken() error = %v", err)
	}

	ok, token, _, _ := GetCasTokenByTicket(ticket)
	if !ok || token == nil {
		t.Fatalf("expected a stored CAS token for ticket %s", ticket)
	}

	if token.Attributes == nil || token.Attributes.UserAttributes == nil {
		t.Fatalf("expected populated CAS user attributes, got %+v", token.Attributes)
	}

	attrs := map[string]string{}
	for _, a := range token.Attributes.UserAttributes.Attributes {
		attrs[a.Name] = a.Value
	}

	// Positive control: legitimate identity attributes must still come
	// through, proving a failure below is specifically about the forbidden
	// fields, not a broken test/environment.
	if attrs["email"] != testUser.Email {
		t.Errorf("expected email attribute %q, got %q (full attrs: %v)", testUser.Email, attrs["email"], attrs)
	}
	if attrs["displayName"] != testUser.DisplayName {
		t.Errorf("expected displayName attribute %q, got %q (full attrs: %v)", testUser.DisplayName, attrs["displayName"], attrs)
	}
	if token.Attributes.Email != testUser.Email {
		t.Errorf("expected typed Attributes.Email %q, got %q", testUser.Email, token.Attributes.Email)
	}

	for _, forbidden := range forbiddenCasAttributeNames {
		if v, ok := attrs[forbidden]; ok {
			t.Errorf("CAS userAttributes leaked forbidden internal field %q = %q", forbidden, v)
		}
	}
}
