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
	"time"

	"github.com/pquerna/otp/totp"
)

// TestMfaSetupEnable_RequiresValidatedPasscode is a regression test for the
// "MFA setup/enable activates a second factor without validating a one-time
// passcode" vulnerability.
//
// Invariant: a user must not be able to turn on an MFA method on their account
// without first proving control of the authenticator by entering a correct
// one-time passcode. The setup/enable step must therefore refuse to proceed to
// Enable() unless a passcode that validates against the pending secret is
// supplied.
//
// This asserts the proof-of-possession gate that MfaSetupEnable() consults
// before calling mfaUtil.Enable(user). Before the fix there was no such gate:
// the enable path was reachable with an attacker-chosen secret and no passcode
// at all.
func TestMfaSetupEnable_RequiresValidatedPasscode(t *testing.T) {
	// A concrete TOTP secret the caller "chose" during setup/initiate.
	const secret = "JBSWY3DPEHPK3PXP"

	newUtil := func() MfaInterface {
		return GetMfaUtil(TotpType, &MfaProps{MfaType: TotpType, Secret: secret})
	}

	// 1) EXPLOIT SHAPE — no passcode supplied. The gate must reject, so the
	//    caller can never reach Enable() without proving possession.
	if err := RequireMfaSetupVerified(newUtil(), ""); err == nil {
		t.Fatalf("INVARIANT VIOLATED: setup/enable gate accepted an EMPTY passcode; " +
			"an attacker-chosen secret would become the account's trusted second " +
			"factor with no proof of possession")
	}

	// 2) Wrong passcode must also be rejected — the gate is a real check, not
	//    merely a presence check.
	if err := RequireMfaSetupVerified(newUtil(), "000000"); err == nil {
		t.Fatalf("INVARIANT VIOLATED: setup/enable gate accepted an INCORRECT passcode; " +
			"proof of possession was not enforced")
	}

	// 3) CONTROL — a correct passcode derived from the pending secret is
	//    accepted, so the fix does not break the legitimate setup flow.
	valid, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("test setup error generating a valid passcode: %v", err)
	}
	if err := RequireMfaSetupVerified(newUtil(), valid); err != nil {
		t.Fatalf("legitimate flow broken: gate rejected a CORRECT passcode for the "+
			"pending secret: %v", err)
	}
}
