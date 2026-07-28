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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// ── DPoP proof construction helpers (mirrors RFC 9449 §4.2), local to this test ──

func dpopTestB64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func dpopTestFixedWidth(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// signTestDPoPProof builds and signs a DPoP proof JWT with the given EC key, mirroring the
// construction used by a real DPoP client (and by the finding's proof-of-concept).
func signTestDPoPProof(t *testing.T, key *ecdsa.PrivateKey, htm, htu, jti string, iat time.Time) string {
	t.Helper()

	x := dpopTestFixedWidth(key.PublicKey.X, 32)
	y := dpopTestFixedWidth(key.PublicKey.Y, 32)

	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   dpopTestB64url(x),
			"y":   dpopTestB64url(y),
		},
	}
	payload := map[string]interface{}{
		"htm": htm,
		"htu": htu,
		"jti": jti,
		"iat": iat.Unix(),
	}

	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal DPoP header: %v", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal DPoP payload: %v", err)
	}
	signingInput := dpopTestB64url(hb) + "." + dpopTestB64url(pb)

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("failed to sign DPoP proof: %v", err)
	}
	sig := append(dpopTestFixedWidth(r, 32), dpopTestFixedWidth(s, 32)...)

	return signingInput + "." + dpopTestB64url(sig)
}

// TestValidateDPoPProofRejectsReplayedJti asserts the RFC 9449 §11.1 invariant: a DPoP proof
// with a jti that has already been accepted must be rejected, so a captured (access token,
// DPoP proof) pair cannot be replayed to repeat the same request.
func TestValidateDPoPProofRejectsReplayedJti(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	const htm = "GET"
	const htu = "https://127.0.0.1:18000/api/userinfo"
	jti := fmt.Sprintf("test-jti-%d", time.Now().UnixNano())
	proof := signTestDPoPProof(t, key, htm, htu, jti, time.Now())

	// Control: the first use of a fresh, valid, unreplayed proof must succeed.
	if _, err := ValidateDPoPProof(proof, htm, htu, ""); err != nil {
		t.Fatalf("control: first use of a fresh DPoP proof was rejected, want success: %v", err)
	}

	// Invariant under test: replaying the identical proof (same jti) must be rejected.
	if _, err := ValidateDPoPProof(proof, htm, htu, ""); err == nil {
		t.Fatalf("replayed DPoP proof (same jti) was accepted a second time, want rejection per RFC 9449 §11.1")
	}
}

// TestValidateDPoPProofAllowsDistinctJti is the companion control: two proofs from the same
// key with distinct jti values must each be accepted independently, proving the replay guard
// is keyed on jti (and not e.g. on the signing key or htu) and doesn't block legitimate traffic.
func TestValidateDPoPProofAllowsDistinctJti(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	const htm = "GET"
	const htu = "https://127.0.0.1:18000/api/userinfo"
	now := time.Now()

	firstJti := fmt.Sprintf("test-jti-a-%d", now.UnixNano())
	secondJti := fmt.Sprintf("test-jti-b-%d", now.UnixNano())

	first := signTestDPoPProof(t, key, htm, htu, firstJti, now)
	second := signTestDPoPProof(t, key, htm, htu, secondJti, now)

	if _, err := ValidateDPoPProof(first, htm, htu, ""); err != nil {
		t.Fatalf("first proof with a unique jti was rejected: %v", err)
	}
	if _, err := ValidateDPoPProof(second, htm, htu, ""); err != nil {
		t.Fatalf("second proof with a different unique jti was rejected: %v", err)
	}
}
