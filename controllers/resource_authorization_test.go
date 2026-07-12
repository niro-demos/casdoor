// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestCanUploadResourceEnforcesUserAndProviderOwnership(t *testing.T) {
	userA := &object.User{Owner: "tenant", Name: "user-a"}
	userB := &object.User{Owner: "tenant", Name: "user-b"}
	orgAdmin := &object.User{Owner: "tenant", Name: "org-admin", IsAdmin: true}
	globalAdmin := &object.User{Owner: "built-in", Name: "admin", IsAdmin: true}
	tenantProvider := &object.Provider{Owner: "tenant", Name: "tenant-storage"}
	foreignProvider := &object.Provider{Owner: "admin", Name: "global-storage"}

	tests := []struct {
		name          string
		actor         *object.User
		target        *object.User
		provider      *object.Provider
		isGlobalAdmin bool
		want          bool
	}{
		{"self upload through tenant provider", userA, userA, tenantProvider, false, true},
		{"cross-user upload", userA, userB, tenantProvider, false, false},
		{"foreign provider upload", userA, userA, foreignProvider, false, false},
		{"org admin manages tenant user", orgAdmin, userB, tenantProvider, false, true},
		{"org admin cannot use foreign provider", orgAdmin, userB, foreignProvider, false, false},
		{"global admin may manage foreign scope", globalAdmin, userB, foreignProvider, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canUploadResource(tt.actor, tt.target, tt.provider, tt.isGlobalAdmin, true); got != tt.want {
				t.Fatalf("canUploadResource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCanUploadResourceAllowsApplicationConfiguredProvider(t *testing.T) {
	user := &object.User{Owner: "tenant", Name: "user"}
	configuredProvider := &object.Provider{Owner: "admin", Name: "configured-storage"}

	if !canUploadResource(user, user, configuredProvider, false, false) {
		t.Fatal("application-configured provider should remain available to its user")
	}
}
