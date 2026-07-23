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

	"github.com/casdoor/casdoor/i18n"
)

// These tests assert the anti-enumeration invariant for the unauthenticated
// pre-authentication endpoints: for each endpoint, the message returned when the
// account does NOT exist must be textually identical to the message returned when
// the account exists but the requested check fails. If the two differ, an
// anonymous caller can use the response text as a boolean account-existence
// oracle. All tests are pure (no DB / no InitConfig) so they run in CI standalone.

const testLang = "en" // any supported language; "en" keeps assertions readable.

// identifyingMessage is the account-revealing string the vulnerable code emitted
// for the "user == nil" branch. No pre-auth endpoint's not-found message may
// equal it (that is the leak), and — more importantly — the not-found message
// must equal the endpoint's own downstream "unqualified user" message.
func identifyingMessage() string {
	return i18n.Translate(testLang, "general:The user: %s doesn't exist")
}

// TC-2DFC403F — POST /api/login must not distinguish "no such account" from
// "wrong password for an existing account".
func TestLogin_NoAccountEnumeration(t *testing.T) {
	// The message /api/login returns when the account does not exist
	// (CheckUserPassword's user == nil branch).
	notFound := GenericLoginError(SigninReasonUserNotFound, testLang).Error()

	// The generic credential-failure message returned for an existing account
	// with a wrong password (counter-free, so its presence/absence does not leak).
	wrongPassword := i18n.Translate(testLang, "check:password or code is incorrect")

	if notFound != wrongPassword {
		t.Fatalf("account enumeration via /api/login: not-found msg %q != wrong-password msg %q; "+
			"an anonymous caller can distinguish existing from non-existing accounts", notFound, wrongPassword)
	}
	if notFound == identifyingMessage() {
		t.Fatalf("/api/login still returns the account-identifying message %q for a missing user", notFound)
	}
}

// TC-F878364F — GET /api/faceid-signin-begin must not distinguish "no such
// account" from "account exists but has no enrolled face data".
func TestFaceIDSigninBegin_NoAccountEnumeration(t *testing.T) {
	notFound := FaceIDSigninUserNotFoundMessage(testLang)
	unqualified := i18n.Translate(testLang, "check:Face data does not exist, cannot log in")

	if notFound != unqualified {
		t.Fatalf("account enumeration via /api/faceid-signin-begin: not-found msg %q != no-face-data msg %q",
			notFound, unqualified)
	}
	if notFound == identifyingMessage() {
		t.Fatalf("/api/faceid-signin-begin still returns the account-identifying message %q for a missing user", notFound)
	}
}

// TC-F878364F — GET /api/webauthn-signin-begin must not distinguish "no such
// account" from "account exists but has no registered credentials".
func TestWebAuthnSigninBegin_NoAccountEnumeration(t *testing.T) {
	notFound := WebAuthnSigninUserNotFoundMessage(testLang)
	unqualified := i18n.Translate(testLang, "webauthn:Found no credentials for this user")

	if notFound != unqualified {
		t.Fatalf("account enumeration via /api/webauthn-signin-begin: not-found msg %q != no-credentials msg %q",
			notFound, unqualified)
	}
	if notFound == identifyingMessage() {
		t.Fatalf("/api/webauthn-signin-begin still returns the account-identifying message %q for a missing user", notFound)
	}
}

// TC-F878364F — POST /api/verify-code must not distinguish "no such account"
// from a real-but-unqualified user; the not-found branch must fail closed with a
// generic verification message.
func TestVerifyCode_NoAccountEnumeration(t *testing.T) {
	notFound := VerifyCodeUserNotFoundMessage(testLang)

	if notFound == identifyingMessage() {
		t.Fatalf("account enumeration via /api/verify-code: not-found branch still returns the "+
			"account-identifying message %q; it must return a generic verification failure instead", notFound)
	}
	// The substitute must be a real, generic verification message.
	generic := i18n.Translate(testLang, "verification:The verification code has not been sent yet!")
	if notFound != generic {
		t.Fatalf("/api/verify-code not-found message %q is not the expected generic verification failure %q",
			notFound, generic)
	}
}

// TC-F1F1EA69 — GET /.well-known/webfinger must return an identical response for
// a registered and an unregistered email. buildAcctWebFinger is the pure builder
// GetWebFinger uses for the "acct" resource type; it must not branch on whether
// the account exists.
func TestWebFinger_NoAccountEnumeration(t *testing.T) {
	resource := "acct:someone@example.test"
	rels := []string{"http://openid.net/specs/connect/1.0/issuer"}
	issuer := "https://idp.example.test"

	registered := buildAcctWebFinger(resource, rels, issuer)
	unregistered := buildAcctWebFinger(resource, rels, issuer)

	// Same builder, same inputs -> must be equal; the real guard is that the
	// builder takes no "user exists" input at all, so registered vs unregistered
	// callers are handled identically. Assert the response is populated (not the
	// old error path) and stable.
	if registered.Subject != resource {
		t.Fatalf("webfinger subject = %q, want %q (response must be populated identically regardless of account existence)",
			registered.Subject, resource)
	}
	if len(registered.Links) != 1 || registered.Links[0].Href != issuer {
		t.Fatalf("webfinger links = %+v, want a single issuer link %q", registered.Links, issuer)
	}
	if registered.Subject != unregistered.Subject || len(registered.Links) != len(unregistered.Links) {
		t.Fatalf("webfinger response differs between calls: %+v vs %+v", registered, unregistered)
	}
}
