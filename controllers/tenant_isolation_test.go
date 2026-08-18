// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package controllers

import "testing"

func TestCanReadOrganization(t *testing.T) {
	tests := []struct {
		name          string
		sessionUserID string
		resourceOwner string
		globalAdmin   bool
		want          bool
	}{
		{name: "tenant admin cannot read another tenant", sessionUserID: "niro-beta/admin", resourceOwner: "niro-alpha", want: false},
		{name: "tenant admin retains access to own tenant", sessionUserID: "niro-beta/admin", resourceOwner: "niro-beta", want: true},
		{name: "global admin retains cross-tenant access", sessionUserID: "built-in/admin", resourceOwner: "niro-alpha", globalAdmin: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canReadOrganization(tt.sessionUserID, tt.resourceOwner, tt.globalAdmin)
			if err != nil {
				t.Fatalf("canReadOrganization() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("canReadOrganization(%q, %q, %t) = %t, want %t", tt.sessionUserID, tt.resourceOwner, tt.globalAdmin, got, tt.want)
			}
		})
	}
}

func TestReadableRecordOrganization(t *testing.T) {
	if got := readableRecordOrganization("niro-beta", "niro-alpha", false); got != "niro-beta" {
		t.Fatalf("tenant audit filter = %q, want authenticated organization %q", got, "niro-beta")
	}
	if got := readableRecordOrganization("", "niro-alpha", true); got != "niro-alpha" {
		t.Fatalf("global-admin audit filter = %q, want requested organization %q", got, "niro-alpha")
	}
}
