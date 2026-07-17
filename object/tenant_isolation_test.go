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
	"os"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/xorm-io/core"
)

func initTenantIsolationTestOrm(t *testing.T) {
	t.Helper()

	if ormer != nil {
		return
	}

	t.Setenv("driverName", "sqlite")
	t.Setenv("dataSourceName", t.TempDir()+"/casdoor-security-test.db")
	t.Setenv("dbName", "")

	createDatabase = false
	if err := web.LoadAppConfig("ini", "../conf/app.conf"); err != nil {
		t.Fatalf("failed to load app config: %v", err)
	}
	InitAdapter()
	CreateTables()
}

func TestConfigObjectUpdatesKeepUrlOwner(t *testing.T) {
	initTenantIsolationTestOrm(t)

	name := "tenant_isolation_" + utilTestSuffix()

	t.Run("form", func(t *testing.T) {
		original := &Form{Owner: "acme", Name: name, DisplayName: "original", Type: "signup", Tag: "test"}
		if ok, err := AddForm(original); err != nil || !ok {
			t.Fatalf("failed to seed form: ok=%v err=%v", ok, err)
		}
		t.Cleanup(func() {
			_, _ = ormer.Engine.ID(core.PK{"acme", name}).Delete(&Form{})
			_, _ = ormer.Engine.ID(core.PK{"built-in", name}).Delete(&Form{})
		})

		updated := *original
		updated.Owner = "built-in"
		updated.DisplayName = "updated"
		if ok, err := UpdateForm("acme/"+name, &updated); err != nil || !ok {
			t.Fatalf("failed to update form: ok=%v err=%v", ok, err)
		}

		assertStillOwnedByAcme(t, &Form{Owner: "acme", Name: name}, &Form{Owner: "built-in", Name: name})
	})

	t.Run("site", func(t *testing.T) {
		original := &Site{Owner: "acme", Name: name, DisplayName: "original", Domain: "acme.example"}
		if ok, err := AddSite(original); err != nil || !ok {
			t.Fatalf("failed to seed site: ok=%v err=%v", ok, err)
		}
		t.Cleanup(func() {
			_, _ = ormer.Engine.ID(core.PK{"acme", name}).Delete(&Site{})
			_, _ = ormer.Engine.ID(core.PK{"built-in", name}).Delete(&Site{})
		})

		updated := *original
		updated.Owner = "built-in"
		updated.DisplayName = "updated"
		if ok, err := UpdateSiteNoRefresh("acme/"+name, &updated); err != nil || !ok {
			t.Fatalf("failed to update site: ok=%v err=%v", ok, err)
		}

		assertStillOwnedByAcme(t, &Site{Owner: "acme", Name: name}, &Site{Owner: "built-in", Name: name})
	})

	t.Run("adapter", func(t *testing.T) {
		original := &Adapter{Owner: "acme", Name: name, Table: "casbin_rule", Type: "Sqlite", DatabaseType: "sqlite"}
		if ok, err := AddAdapter(original); err != nil || !ok {
			t.Fatalf("failed to seed adapter: ok=%v err=%v", ok, err)
		}
		t.Cleanup(func() {
			_, _ = ormer.Engine.ID(core.PK{"acme", name}).Delete(&Adapter{})
			_, _ = ormer.Engine.ID(core.PK{"built-in", name}).Delete(&Adapter{})
		})

		updated := *original
		updated.Owner = "built-in"
		updated.Table = "casbin_rule_updated"
		if ok, err := UpdateAdapter("acme/"+name, &updated); err != nil || !ok {
			t.Fatalf("failed to update adapter: ok=%v err=%v", ok, err)
		}

		assertStillOwnedByAcme(t, &Adapter{Owner: "acme", Name: name}, &Adapter{Owner: "built-in", Name: name})
	})

	t.Run("agent", func(t *testing.T) {
		original := &Agent{Owner: "acme", Name: name, DisplayName: "original", Url: "https://acme.example", Application: "app-acme"}
		if ok, err := AddAgent(original); err != nil || !ok {
			t.Fatalf("failed to seed agent: ok=%v err=%v", ok, err)
		}
		t.Cleanup(func() {
			_, _ = ormer.Engine.ID(core.PK{"acme", name}).Delete(&Agent{})
			_, _ = ormer.Engine.ID(core.PK{"built-in", name}).Delete(&Agent{})
		})

		updated := *original
		updated.Owner = "built-in"
		updated.DisplayName = "updated"
		if ok, err := UpdateAgent("acme/"+name, &updated); err != nil || !ok {
			t.Fatalf("failed to update agent: ok=%v err=%v", ok, err)
		}

		assertStillOwnedByAcme(t, &Agent{Owner: "acme", Name: name}, &Agent{Owner: "built-in", Name: name})
	})
}

func assertStillOwnedByAcme(t *testing.T, acmeRow interface{}, builtInRow interface{}) {
	t.Helper()

	acmeExists, err := ormer.Engine.Get(acmeRow)
	if err != nil {
		t.Fatalf("failed to read acme row: %v", err)
	}
	builtInExists, err := ormer.Engine.Get(builtInRow)
	if err != nil {
		t.Fatalf("failed to read built-in row: %v", err)
	}

	if !acmeExists || builtInExists {
		t.Fatalf("tenant owner changed: acmeExists=%v builtInExists=%v", acmeExists, builtInExists)
	}
}

func utilTestSuffix() string {
	return fmt.Sprintf("%d_%d", os.Getpid(), len(os.Args))
}
