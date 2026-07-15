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

import (
	"fmt"
	"testing"
	"time"
)

// These tests cover TC-2D55103D: an organization-scoped admin (isGlobalAdmin
// == false) must not be able to relocate a Server or Agent connector record
// they own into another organization's namespace by supplying a different
// `owner` in the update body. This mirrors the organization-boundary guard
// already covered for UpdateSyncer/UpdateWebhook.

func TestUpdateServerRejectsCrossOrgOwnerChange(t *testing.T) {
	InitConfig()

	name := "niro-test-srv-" + util_randSuffix()

	created, err := AddServer(&Server{
		Owner:       "acme",
		Name:        name,
		DisplayName: name,
		Url:         "http://example.com",
		Application: "app-acme",
	})
	if err != nil || !created {
		t.Fatalf("setup: AddServer failed: created=%v err=%v", created, err)
	}
	defer func() {
		_, _ = DeleteServer(&Server{Owner: "acme", Name: name})
		_, _ = DeleteServer(&Server{Owner: "built-in", Name: name})
	}()

	// Attack: an org-scoped admin (isGlobalAdmin=false) updates the record
	// via its acme id, but supplies owner="built-in" in the body.
	hijack := &Server{
		Owner:       "built-in",
		Name:        name,
		DisplayName: "hijacked-" + name,
		Url:         "http://attacker.evil.example",
		Application: "app-built-in",
	}
	_, err = UpdateServer("acme/"+name, hijack, false, "en")
	if err == nil {
		t.Fatalf("INVARIANT VIOLATED: org-scoped admin was able to move server %q from acme into built-in without error", name)
	}

	moved, err := getServer("built-in", name)
	if err != nil {
		t.Fatalf("getServer(built-in): unexpected error: %v", err)
	}
	if moved != nil {
		t.Fatalf("INVARIANT VIOLATED: server %q now exists under owner=built-in (url=%s, application=%s)", name, moved.Url, moved.Application)
	}

	still, err := getServer("acme", name)
	if err != nil {
		t.Fatalf("getServer(acme): unexpected error: %v", err)
	}
	if still == nil || still.Owner != "acme" {
		t.Fatalf("INVARIANT VIOLATED: server %q no longer exists under owner=acme", name)
	}

	// Positive control: a legitimate same-org update (owner unchanged) by
	// the same non-global-admin caller must still succeed.
	legit := &Server{
		Owner:       "acme",
		Name:        name,
		DisplayName: "renamed-" + name,
		Url:         "http://example.com",
		Application: "app-acme",
	}
	affected, err := UpdateServer("acme/"+name, legit, false, "en")
	if err != nil || !affected {
		t.Fatalf("positive control: same-org update must succeed, got affected=%v err=%v", affected, err)
	}
	got, err := getServer("acme", name)
	if err != nil {
		t.Fatalf("getServer(acme) after legit update: unexpected error: %v", err)
	}
	if got == nil || got.DisplayName != "renamed-"+name {
		t.Fatalf("positive control: same-org update did not take effect, got %+v", got)
	}

	// Global admins must still be able to migrate a record across orgs.
	migrate := &Server{
		Owner:       "built-in",
		Name:        name,
		DisplayName: "migrated-" + name,
		Url:         "http://example.com",
		Application: "app-built-in",
	}
	affected, err = UpdateServer("acme/"+name, migrate, true, "en")
	if err != nil || !affected {
		t.Fatalf("global admin cross-org migration must succeed, got affected=%v err=%v", affected, err)
	}
	migratedOk, err := getServer("built-in", name)
	if err != nil {
		t.Fatalf("getServer(built-in) after global-admin migration: unexpected error: %v", err)
	}
	if migratedOk == nil || migratedOk.Owner != "built-in" {
		t.Fatalf("global admin migration did not take effect, got %+v", migratedOk)
	}
}

func TestUpdateAgentRejectsCrossOrgOwnerChange(t *testing.T) {
	InitConfig()

	name := "niro-test-agent-" + util_randSuffix()

	created, err := AddAgent(&Agent{
		Owner:       "acme",
		Name:        name,
		DisplayName: name,
		Url:         "http://example.com",
		Application: "app-acme",
	})
	if err != nil || !created {
		t.Fatalf("setup: AddAgent failed: created=%v err=%v", created, err)
	}
	defer func() {
		_, _ = DeleteAgent(&Agent{Owner: "acme", Name: name})
		_, _ = DeleteAgent(&Agent{Owner: "built-in", Name: name})
	}()

	hijack := &Agent{
		Owner:       "built-in",
		Name:        name,
		DisplayName: "hijacked-" + name,
		Url:         "http://attacker.evil.example",
		Application: "app-built-in",
	}
	_, err = UpdateAgent("acme/"+name, hijack, false, "en")
	if err == nil {
		t.Fatalf("INVARIANT VIOLATED: org-scoped admin was able to move agent %q from acme into built-in without error", name)
	}

	moved, err := getAgent("built-in", name)
	if err != nil {
		t.Fatalf("getAgent(built-in): unexpected error: %v", err)
	}
	if moved != nil {
		t.Fatalf("INVARIANT VIOLATED: agent %q now exists under owner=built-in (url=%s, application=%s)", name, moved.Url, moved.Application)
	}

	still, err := getAgent("acme", name)
	if err != nil {
		t.Fatalf("getAgent(acme): unexpected error: %v", err)
	}
	if still == nil || still.Owner != "acme" {
		t.Fatalf("INVARIANT VIOLATED: agent %q no longer exists under owner=acme", name)
	}

	// Positive control: a legitimate same-org update (owner unchanged) by
	// the same non-global-admin caller must still succeed.
	legit := &Agent{
		Owner:       "acme",
		Name:        name,
		DisplayName: "renamed-" + name,
		Url:         "http://example.com",
		Application: "app-acme",
	}
	affected, err := UpdateAgent("acme/"+name, legit, false, "en")
	if err != nil || !affected {
		t.Fatalf("positive control: same-org update must succeed, got affected=%v err=%v", affected, err)
	}
	got, err := getAgent("acme", name)
	if err != nil {
		t.Fatalf("getAgent(acme) after legit update: unexpected error: %v", err)
	}
	if got == nil || got.DisplayName != "renamed-"+name {
		t.Fatalf("positive control: same-org update did not take effect, got %+v", got)
	}

	// Global admins must still be able to migrate a record across orgs.
	migrate := &Agent{
		Owner:       "built-in",
		Name:        name,
		DisplayName: "migrated-" + name,
		Url:         "http://example.com",
		Application: "app-built-in",
	}
	affected, err = UpdateAgent("acme/"+name, migrate, true, "en")
	if err != nil || !affected {
		t.Fatalf("global admin cross-org migration must succeed, got affected=%v err=%v", affected, err)
	}
	migratedOk, err := getAgent("built-in", name)
	if err != nil {
		t.Fatalf("getAgent(built-in) after global-admin migration: unexpected error: %v", err)
	}
	if migratedOk == nil || migratedOk.Owner != "built-in" {
		t.Fatalf("global admin migration did not take effect, got %+v", migratedOk)
	}
}

func util_randSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
