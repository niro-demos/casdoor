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

const (
	anonymousLoginFailureMessage    = "password or code is incorrect"
	anonymousWebAuthnFailureMessage = "Unable to start WebAuthn sign-in"
	anonymousRecoveryMessage        = "If the account can receive a code, it will be sent"
)

func anonymousLoginFailure(_ string) string {
	return anonymousLoginFailureMessage
}

func anonymousWebAuthnFailure(_ string) string {
	return anonymousWebAuthnFailureMessage
}

func anonymousRecoveryResult(_ string) string {
	return anonymousRecoveryMessage
}
