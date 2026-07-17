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

//go:build !skipCi

package object

import "testing"

// TestUpdateTicketRejectsCrossOrgOwnerChange is the regression test for
// TC-7F4E15B4: an org-scoped (non-global) admin must not be able to relocate
// a ticket into a different organization's namespace by setting a mismatched
// `owner` field in the update-ticket request body, even though the `id`
// query parameter still names a ticket the caller legitimately manages.
func TestUpdateTicketRejectsCrossOrgOwnerChange(t *testing.T) {
	InitConfig()

	sourceOwner := "niro-test-org-a"
	targetOwner := "niro-test-org-b"
	name := "niro-test-ticket-cross-org"
	id := sourceOwner + "/" + name

	seed := &Ticket{
		Owner: sourceOwner,
		Name:  name,
		Title: "Support Request",
		User:  sourceOwner + "/alice",
		State: "Open",
	}

	// Clean up any leftovers from a previous failed run, then seed fresh.
	_, _ = DeleteTicket(&Ticket{Owner: sourceOwner, Name: name})
	_, _ = DeleteTicket(&Ticket{Owner: targetOwner, Name: name})

	ok, err := AddTicket(seed)
	if err != nil || !ok {
		t.Fatalf("setup: AddTicket failed: ok=%v err=%v", ok, err)
	}
	defer func() {
		_, _ = DeleteTicket(&Ticket{Owner: sourceOwner, Name: name})
		_, _ = DeleteTicket(&Ticket{Owner: targetOwner, Name: name})
	}()

	// Attack: caller is authorized for id=sourceOwner/name (an org-scoped,
	// non-global admin), but the request body's owner names a different org.
	malicious := &Ticket{
		Owner: targetOwner,
		Name:  name,
		Title: "MOVED-BY-ATTACKER",
		User:  sourceOwner + "/alice",
		State: "Open",
	}

	_, err = UpdateTicket(id, malicious, false, "en")
	if err == nil {
		t.Fatalf("invariant violated: UpdateTicket allowed a non-global-admin to change owner from %q to %q without error", sourceOwner, targetOwner)
	}

	relocated, getErr := getTicket(targetOwner, name)
	if getErr != nil {
		t.Fatalf("getTicket(%s) failed: %v", targetOwner, getErr)
	}
	if relocated != nil {
		t.Fatalf("invariant violated: ticket record was relocated into %q", targetOwner)
	}

	original, getErr := getTicket(sourceOwner, name)
	if getErr != nil {
		t.Fatalf("getTicket(%s) failed: %v", sourceOwner, getErr)
	}
	if original == nil {
		t.Fatalf("invariant violated: ticket record disappeared from its own org %q", sourceOwner)
	}
	if original.Title != seed.Title {
		t.Fatalf("invariant violated: ticket record was mutated by the rejected cross-org update, Title=%q", original.Title)
	}

	// Control: a same-org update (legitimate) must still succeed, proving the
	// rejection above is about the owner mismatch, not a broken environment.
	legit := &Ticket{
		Owner: sourceOwner,
		Name:  name,
		Title: "legit-same-org-update",
		User:  sourceOwner + "/alice",
		State: "Closed",
	}
	ok, err = UpdateTicket(id, legit, false, "en")
	if err != nil || !ok {
		t.Fatalf("control failed: same-org update should succeed, ok=%v err=%v", ok, err)
	}
}
