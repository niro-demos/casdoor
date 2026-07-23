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

import (
	"encoding/json"
	"testing"

	"github.com/casdoor/casdoor/object"
)

// Regression test for the audit-log forgery via POST /api/add-record.
//
// Invariant: a record created through the public AddRecord handler must be
// attributed to the CALLER's own authenticated identity and real network
// origin. A non-admin caller must never be able to fabricate the identity/
// outcome fields (user, owner, name, organization, clientIp) so the record is
// falsely attributed to a different principal.
//
// This exercises sanitizeRecordForAdd directly (the server-side derivation
// applied after unmarshal, before persistence) rather than the live DB path,
// so it runs in the isolated native suite with no seeded target.
func TestSanitizeRecordForAddForcesCallerIdentity(t *testing.T) {
	// The forged body a non-admin caller (real identity org-beta/beta-user)
	// submits: owner/name set to itself to clear the router Casbin gate, but
	// user/clientIp/action/statusCode/response fabricated to attribute a
	// destructive action to a DIFFERENT principal.
	body := `{"owner":"org-beta","name":"beta-user","organization":"org-beta",` +
		`"user":"org-beta/forged-superadmin","action":"delete-user",` +
		`"clientIp":"9.9.9.9","requestUri":"/api/delete-user",` +
		`"response":"{status:\"ok\"}","statusCode":200,` +
		`"detail":"FORGED: superadmin deleted all users"}`

	var record object.Record
	if err := json.Unmarshal([]byte(body), &record); err != nil {
		t.Fatalf("unmarshal forged body: %v", err)
	}

	// The trusted context the server derives from the session + transport,
	// NOT from the body.
	const (
		sessionUserId = "org-beta/beta-user"
		realClientIp  = "203.0.113.7"
	)

	sanitizeRecordForAdd(&record, sessionUserId, realClientIp)

	// --- Invariant: attribution is the caller's, never the forged body. ---
	if record.User != sessionUserId {
		t.Errorf("record.User = %q; want caller identity %q (forged attribution accepted)", record.User, sessionUserId)
	}
	if record.User == "org-beta/forged-superadmin" {
		t.Errorf("record.User retained forged principal %q", record.User)
	}
	if record.Owner != "org-beta" || record.Name != "beta-user" {
		t.Errorf("record owner/name = %q/%q; want caller org-beta/beta-user", record.Owner, record.Name)
	}
	if record.Organization != "org-beta" {
		t.Errorf("record.Organization = %q; want caller org org-beta", record.Organization)
	}
	if record.ClientIp != realClientIp {
		t.Errorf("record.ClientIp = %q; want real transport IP %q (forged 9.9.9.9 accepted)", record.ClientIp, realClientIp)
	}
	if record.ClientIp == "9.9.9.9" {
		t.Errorf("record.ClientIp retained forged value 9.9.9.9")
	}

	// The fabricated outcome fields must not be trusted from the client: a
	// caller cannot stamp a fake "200 ok" delete-user result into the trail.
	if record.StatusCode != 0 {
		t.Errorf("record.StatusCode = %d; want 0 (client must not set the outcome code)", record.StatusCode)
	}
	if record.Response != "" {
		t.Errorf("record.Response = %q; want empty (client must not set the outcome body)", record.Response)
	}
}

// A caller submitting an HONEST record (attributed to itself) is still accepted
// and its non-attribution content preserved. This isolates the failure above to
// the forgery invariant rather than a blanket rejection of the endpoint.
func TestSanitizeRecordForAddPreservesHonestContent(t *testing.T) {
	body := `{"owner":"org-beta","name":"beta-user","organization":"org-beta",` +
		`"user":"org-beta/beta-user","action":"login","detail":"honest entry"}`

	var record object.Record
	if err := json.Unmarshal([]byte(body), &record); err != nil {
		t.Fatalf("unmarshal honest body: %v", err)
	}

	sanitizeRecordForAdd(&record, "org-beta/beta-user", "203.0.113.7")

	if record.User != "org-beta/beta-user" {
		t.Errorf("record.User = %q; want org-beta/beta-user", record.User)
	}
	if record.Detail != "honest entry" {
		t.Errorf("record.Detail = %q; honest non-attribution content must be preserved", record.Detail)
	}
	if record.Action != "login" {
		t.Errorf("record.Action = %q; want login", record.Action)
	}
}
