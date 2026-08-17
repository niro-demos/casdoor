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
	"path/filepath"
	"testing"

	"github.com/casdoor/casdoor/util"
)

func TestGetRecordsForOrganizationScopesUnpaginatedRecords(t *testing.T) {
	initRecordTestAdapter(t)

	alphaRecord := &Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: "record-test-alpha",
		Action:       "login",
		Method:       "GET",
	}
	betaRecord := &Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: "record-test-beta",
		Action:       "login",
		Method:       "GET",
	}

	for _, record := range []*Record{alphaRecord, betaRecord} {
		if _, err := addRecord(record); err != nil {
			t.Fatalf("addRecord(%s): %v", record.Organization, err)
		}
		t.Cleanup(func() {
			if _, err := ormer.Engine.ID(record.Id).Delete(&Record{}); err != nil {
				t.Fatalf("cleanup record %d: %v", record.Id, err)
			}
		})
	}

	records, err := GetRecordsForOrganization("record-test-alpha")
	if err != nil {
		t.Fatalf("GetRecordsForOrganization() error = %v", err)
	}

	var sawAlpha, sawBeta bool
	for _, record := range records {
		switch record.Name {
		case alphaRecord.Name:
			sawAlpha = true
		case betaRecord.Name:
			sawBeta = true
		}
	}

	if !sawAlpha {
		t.Fatalf("GetRecordsForOrganization() omitted allowed alpha record %q", alphaRecord.Name)
	}
	if sawBeta {
		t.Fatalf("GetRecordsForOrganization() returned cross-tenant beta record %q", betaRecord.Name)
	}
}

func initRecordTestAdapter(t *testing.T) {
	t.Helper()

	oldOrmer := ormer
	adapter, err := NewAdapter("sqlite", filepath.Join(t.TempDir(), "records.db"), "")
	if err != nil {
		t.Fatalf("NewAdapter(sqlite): %v", err)
	}
	ormer = adapter
	if err := ormer.Engine.Sync2(new(Record)); err != nil {
		t.Fatalf("sync Record table: %v", err)
	}

	t.Cleanup(func() {
		if err := adapter.Engine.Close(); err != nil {
			t.Fatalf("close test adapter: %v", err)
		}
		ormer = oldOrmer
	})
}
