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

// TestGeneratedPgtIsNotValidUntilStored is a regression test for
// TC-4C22EBF1: a CAS proxy-granting ticket id must not be
// valid/redeemable (GetCasTokenByPgt) until the caller explicitly activates
// it via StoreCasTokenForPgt - which CasP3ProxyValidate (controllers/cas.go)
// must only do after the pgtUrl callback has confirmed success. Generating
// an id alone (GenerateCasPgt) must never make it redeemable.
func TestGeneratedPgtIsNotValidUntilStored(t *testing.T) {
	token := &CasAuthenticationSuccess{User: "alice", ProxyGrantingTicket: "PGTIOU-test"}

	pgt := GenerateCasPgt()
	if pgt == "" {
		t.Fatalf("GenerateCasPgt() returned an empty id")
	}

	// Before activation: must not be redeemable.
	if ok, _, _, _ := GetCasTokenByPgt(pgt); ok {
		t.Fatalf("GetCasTokenByPgt(%q) = true before StoreCasTokenForPgt was ever called; a generated-but-unconfirmed PGT must not be valid", pgt)
	}

	// Activate it (simulating a successful pgtUrl callback).
	StoreCasTokenForPgt(pgt, token, "https://service.example.com/callback", "org/alice")

	// After activation: must be redeemable exactly once.
	ok, gotToken, gotService, gotUserId := GetCasTokenByPgt(pgt)
	if !ok {
		t.Fatalf("GetCasTokenByPgt(%q) = false after StoreCasTokenForPgt; the activated PGT must be redeemable", pgt)
	}
	if gotToken != token || gotService != "https://service.example.com/callback" || gotUserId != "org/alice" {
		t.Fatalf("GetCasTokenByPgt(%q) returned unexpected data: token=%v service=%q userId=%q", pgt, gotToken, gotService, gotUserId)
	}

	// GetCasTokenByPgt deletes on read (single redemption): a second
	// redemption attempt must fail.
	if ok, _, _, _ := GetCasTokenByPgt(pgt); ok {
		t.Fatalf("GetCasTokenByPgt(%q) = true on a second call; a PGT must only be redeemable once", pgt)
	}
}

// TestUnstoredPgtNeverBecomesValid is the positive control for the test
// above: a PGT id that is generated but never activated (e.g. because the
// pgtUrl callback failed) must remain permanently unredeemable - it does
// not become valid "eventually" or as a side effect of any other call.
func TestUnstoredPgtNeverBecomesValid(t *testing.T) {
	pgt := GenerateCasPgt()

	// Unrelated activity on the pgt map (another ticket entirely) must not
	// make our never-activated pgt valid.
	other := GenerateCasPgt()
	StoreCasTokenForPgt(other, &CasAuthenticationSuccess{User: "bob"}, "https://other.example.com/callback", "org/bob")

	if ok, _, _, _ := GetCasTokenByPgt(pgt); ok {
		t.Fatalf("GetCasTokenByPgt(%q) = true for a PGT that was never activated via StoreCasTokenForPgt", pgt)
	}
}
