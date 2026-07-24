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
)

// TestResolveMfaEnableSecret_TotpProofOfPossession pins the security invariant
// behind TC-D4413C36:
//
// A user must not be able to activate the authenticator-app (TOTP) MFA factor
// on their account unless they have first PROVEN possession of the secret by
// passing the passcode-verify step (`/api/mfa/setup/verify`) in the SAME
// session. The three-step handshake (initiate -> verify -> enable) is only
// safe if `enable` derives the secret it persists from the session-recorded
// verified state, never from a value the client supplies at enable time.
//
// ResolveMfaEnableSecret is the single decision point the enable handler routes
// through for TOTP. This test asserts:
//
//   - RED (the bug): when the session holds no verified TOTP secret, enable must
//     be rejected regardless of what secret the request carries. On the unfixed
//     code this guarantee does not exist at all (the handler trusts the request
//     `secret` field directly), so this case reproduces the vulnerability.
//   - GREEN control: when the session holds a verified secret (verify succeeded
//     for this session), enable proceeds and persists exactly that
//     session-verified secret — proving the check is specific to the missing
//     proof of possession, not a blanket refusal that would break legitimate
//     setup.
func TestResolveMfaEnableSecret_TotpProofOfPossession(t *testing.T) {
	const verified = "JBSWY3DPEHPK3PXP" // a secret the session proved possession of

	// --- The exploit: no verified secret in session, attacker supplies one. ---
	// This is exactly the PoC: skip initiate+verify, POST enable with an
	// attacker-chosen secret. The invariant demands rejection.
	got, err := ResolveMfaEnableSecret(TotpType, "", "AAAQEAYEAUDAOCAJ")
	if err == nil {
		t.Fatalf("SECURITY: enable was allowed with NO verified session secret "+
			"(returned secret %q) — an attacker-chosen TOTP factor can be planted "+
			"without any proof of possession", got)
	}

	// Even an empty request secret must still be rejected when nothing is verified.
	if _, err := ResolveMfaEnableSecret(TotpType, "", ""); err == nil {
		t.Fatalf("SECURITY: enable was allowed with no verified session secret and no request secret")
	}

	// --- Green control: the legitimate path must still work. ---
	// verify succeeded in-session, so enable proceeds and uses the verified secret.
	got, err = ResolveMfaEnableSecret(TotpType, verified, "AAAQEAYEAUDAOCAJ")
	if err != nil {
		t.Fatalf("legitimate enable after a successful verify was rejected: %v", err)
	}
	if got != verified {
		t.Fatalf("enable must persist the SESSION-VERIFIED secret, not the request "+
			"secret: got %q, want %q", got, verified)
	}

	// And when the request omits a secret entirely (the fixed client stops
	// sending it), the session-verified secret is still the one persisted.
	got, err = ResolveMfaEnableSecret(TotpType, verified, "")
	if err != nil {
		t.Fatalf("legitimate enable with no request secret was rejected: %v", err)
	}
	if got != verified {
		t.Fatalf("enable must persist the session-verified secret: got %q, want %q", got, verified)
	}
}
