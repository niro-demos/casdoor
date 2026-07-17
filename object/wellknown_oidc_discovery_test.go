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

package object

import (
	"fmt"
	"testing"
	"time"
)

// TestGetWebFingerDoesNotLeakAccountExistence guards against the
// unauthenticated user-enumeration oracle in the WebFinger discovery
// endpoint (TC-ED415704 / GET /.well-known/webfinger).
//
// Invariant: GetWebFinger must not let a caller distinguish a registered
// account from a fabricated one by observing a different outcome (error vs.
// success, or a different response shape) for the two cases.
func TestGetWebFingerDoesNotLeakAccountExistence(t *testing.T) {
	InitConfig()

	// A registered account: insert a user row directly (bypassing the
	// higher-level AddUser business rules, which require a pre-existing
	// organization/application — irrelevant to this lookup-only endpoint).
	suffix := time.Now().UnixNano()
	owner := "built-in"
	name := fmt.Sprintf("niro_webfinger_user_%d", suffix)
	email := fmt.Sprintf("niro-webfinger-%d@example.com", suffix)

	user := &User{
		Owner: owner,
		Name:  name,
		Email: email,
	}
	affected, err := ormer.Engine.Insert(user)
	if err != nil {
		t.Fatalf("failed to insert fixture user: %v", err)
	}
	if affected == 0 {
		t.Fatalf("fixture user was not inserted")
	}
	defer func() {
		if _, err := ormer.Engine.Delete(user); err != nil {
			t.Logf("cleanup: failed to delete fixture user: %v", err)
		}
	}()

	// A guaranteed-nonexistent account on the same domain.
	ghostEmail := fmt.Sprintf("niro-webfinger-ghost-%d@example.com", suffix)

	knownResource := fmt.Sprintf("acct:%s", email)
	ghostResource := fmt.Sprintf("acct:%s", ghostEmail)

	knownWf, knownErr := GetWebFinger(knownResource, nil, "example.com", "")
	ghostWf, ghostErr := GetWebFinger(ghostResource, nil, "example.com", "")

	// Positive control: a syntactically invalid resource must still error,
	// proving the function actually validates input rather than swallowing
	// every error unconditionally.
	if _, err := GetWebFinger("not-a-valid-resource", nil, "example.com", ""); err == nil {
		t.Fatalf("expected an error for a malformed resource, got nil (harness/positive-control failure)")
	}

	if knownErr != nil {
		t.Fatalf("known-account WebFinger lookup returned unexpected error: %v", knownErr)
	}
	if ghostErr != nil {
		t.Fatalf("SECURITY REGRESSION (TC-ED415704): fabricated-account WebFinger lookup returned an error (%v) while the known-account lookup succeeded. "+
			"This is the enumeration oracle: an unauthenticated caller can tell a registered account from an unregistered one by whether this endpoint errors.", ghostErr)
	}

	if knownWf.Subject != knownResource {
		t.Fatalf("known-account response Subject = %q, want %q", knownWf.Subject, knownResource)
	}
	if ghostWf.Subject != ghostResource {
		t.Fatalf("fabricated-account response Subject = %q, want %q", ghostWf.Subject, ghostResource)
	}
}
