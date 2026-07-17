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

package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestUnpaginatedRecordsAreScopedForOrganizationAdmin(t *testing.T) {
	var globalQueried bool
	var scopedOrganization string

	records, err := getUnpaginatedRecordsForAdmin(false, "acme", recordQueries{
		getAll: func() ([]*object.Record, error) {
			globalQueried = true
			return []*object.Record{{Organization: "built-in", User: "admin"}}, nil
		},
		getByField: func(record *object.Record) ([]*object.Record, error) {
			scopedOrganization = record.Organization
			return []*object.Record{{Organization: record.Organization, User: "acme-admin"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("getUnpaginatedRecordsForAdmin() returned error: %v", err)
	}
	if globalQueried {
		t.Fatal("organization admin used the instance-wide record query")
	}
	if scopedOrganization != "acme" {
		t.Fatalf("scoped organization = %q, want acme", scopedOrganization)
	}
	if len(records) != 1 || records[0].Organization != "acme" {
		t.Fatalf("records = %#v, want only acme records", records)
	}
}

func TestUnpaginatedRecordsStayGlobalForGlobalAdmin(t *testing.T) {
	var scopedQueried bool

	records, err := getUnpaginatedRecordsForAdmin(true, "", recordQueries{
		getAll: func() ([]*object.Record, error) {
			return []*object.Record{
				{Organization: "built-in", User: "admin"},
				{Organization: "acme", User: "alice"},
			}, nil
		},
		getByField: func(record *object.Record) ([]*object.Record, error) {
			scopedQueried = true
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("getUnpaginatedRecordsForAdmin() returned error: %v", err)
	}
	if scopedQueried {
		t.Fatal("global admin should use the instance-wide record query")
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}
}
