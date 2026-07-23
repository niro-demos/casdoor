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

import "github.com/casdoor/casdoor/i18n"

// This file centralizes the uniform, non-identifying error messages that the
// unauthenticated pre-authentication endpoints return, so that an anonymous
// caller cannot tell whether a given username/organization/email belongs to a
// real account by comparing response text.
//
// The invariant these helpers enforce: on a pre-auth path, the "no such user"
// case and the "user exists but this check failed" case must be textually
// indistinguishable. Each helper returns exactly the message the endpoint
// already produces for the real-but-unqualified user, so the "user == nil"
// branch can reuse it verbatim.
//
// These are deliberately unconditional (they do NOT depend on the optional
// `enableErrorMask` config flag, whose shipped default is off): the leak exists
// on these anonymous routes regardless of that flag, so the uniform response is
// always applied here.

// GenericLoginError is the uniform message returned by /api/login for every
// credential failure — "no such account" and "wrong password" alike — so the
// two cannot be distinguished. The caller supplies the audit reason so that the
// structured SigninError.Reason (used only for internal logging) stays accurate
// while the externally visible message is normalized.
//
// The message is the counter-free generic string; the remaining-chances counter
// is intentionally omitted from the external message because its presence
// (existing account) vs absence (no such account) would itself leak existence.
func GenericLoginError(reason string, lang string) *SigninError {
	return newSigninError(reason, i18n.Translate(lang, "check:password or code is incorrect"))
}

// FaceIDSigninUserNotFoundMessage is the message FaceIDSigninBegin returns when
// the user does not exist. It is identical to the message returned when the user
// exists but has no enrolled face data, so account existence cannot be inferred.
func FaceIDSigninUserNotFoundMessage(lang string) string {
	return i18n.Translate(lang, "check:Face data does not exist, cannot log in")
}

// WebAuthnSigninUserNotFoundMessage is the message WebAuthnSigninBegin returns
// when the user does not exist. It is identical to the message returned when the
// user exists but has no registered credentials, so account existence cannot be
// inferred.
func WebAuthnSigninUserNotFoundMessage(lang string) string {
	return i18n.Translate(lang, "webauthn:Found no credentials for this user")
}

// VerifyCodeUserNotFoundMessage is the message VerifyCode returns when the user
// does not exist. It is a generic verification failure that does not reveal
// whether the account exists.
func VerifyCodeUserNotFoundMessage(lang string) string {
	return i18n.Translate(lang, "verification:The verification code has not been sent yet!")
}
