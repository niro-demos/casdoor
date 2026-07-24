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
	"fmt"
	"testing"
	"time"
)

const casbinOwnerUpdateModelText = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

func TestCasbinConfigUpdatesDoNotMoveTenantObjectsToBuiltIn(t *testing.T) {
	t.Setenv("driverName", "sqlite3")
	t.Setenv("dataSourceName", t.TempDir()+"/casdoor-owner-update.db")
	t.Setenv("dbName", "")
	originalCreateDatabase := createDatabase
	t.Cleanup(func() {
		createDatabase = originalCreateDatabase
	})
	createDatabase = false
	InitConfig()

	suffix := fmt.Sprintf("owner-update-%d", time.Now().UnixNano())
	sourceOwner := "test-org"
	targetOwner := "built-in"

	tests := []struct {
		name    string
		source  string
		target  string
		create  func(string)
		update  func(string, string) (bool, error)
		get     func(string, string) (bool, error)
		cleanup func(string, string)
	}{
		{
			name:   "model",
			source: "model-" + suffix,
			target: "global-model-" + suffix,
			create: func(name string) {
				affected, err := AddModel(&Model{Owner: sourceOwner, Name: name, DisplayName: name, ModelText: casbinOwnerUpdateModelText})
				mustTestAction(t, affected, err)
			},
			update: func(sourceName, targetName string) (bool, error) {
				return UpdateModel(sourceOwner+"/"+sourceName, &Model{Owner: targetOwner, Name: targetName, DisplayName: targetName, ModelText: casbinOwnerUpdateModelText}, false)
			},
			get: func(owner, name string) (bool, error) {
				model, err := getModel(owner, name)
				return model != nil, err
			},
			cleanup: func(owner, name string) {
				_, _ = DeleteModel(&Model{Owner: owner, Name: name})
			},
		},
		{
			name:   "adapter",
			source: "adapter-" + suffix,
			target: "global-adapter-" + suffix,
			create: func(name string) {
				affected, err := AddAdapter(&Adapter{Owner: sourceOwner, Name: name, Table: "permission_rule", UseSameDb: true, Type: "Database"})
				mustTestAction(t, affected, err)
			},
			update: func(sourceName, targetName string) (bool, error) {
				return UpdateAdapter(sourceOwner+"/"+sourceName, &Adapter{Owner: targetOwner, Name: targetName, Table: "permission_rule", UseSameDb: true, Type: "Database"}, false)
			},
			get: func(owner, name string) (bool, error) {
				adapter, err := getAdapter(owner, name)
				return adapter != nil, err
			},
			cleanup: func(owner, name string) {
				_, _ = DeleteAdapter(&Adapter{Owner: owner, Name: name})
			},
		},
		{
			name:   "permission",
			source: "permission-" + suffix,
			target: "global-permission-" + suffix,
			create: func(name string) {
				affected, err := AddPermission(newOwnerUpdatePermission(sourceOwner, name))
				mustTestAction(t, affected, err)
			},
			update: func(sourceName, targetName string) (bool, error) {
				return UpdatePermission(sourceOwner+"/"+sourceName, newOwnerUpdatePermission(targetOwner, targetName), false)
			},
			get: func(owner, name string) (bool, error) {
				permission, err := getPermission(owner, name)
				return permission != nil, err
			},
			cleanup: func(owner, name string) {
				_, _ = DeletePermission(&Permission{Owner: owner, Name: name})
			},
		},
		{
			name:   "enforcer",
			source: "enforcer-" + suffix,
			target: "global-enforcer-" + suffix,
			create: func(name string) {
				affected, err := AddEnforcer(&Enforcer{Owner: sourceOwner, Name: name, DisplayName: name})
				mustTestAction(t, affected, err)
			},
			update: func(sourceName, targetName string) (bool, error) {
				return UpdateEnforcer(sourceOwner+"/"+sourceName, &Enforcer{Owner: targetOwner, Name: targetName, DisplayName: targetName}, false)
			},
			get: func(owner, name string) (bool, error) {
				enforcer, err := getEnforcer(owner, name)
				return enforcer != nil, err
			},
			cleanup: func(owner, name string) {
				_, _ = DeleteEnforcer(&Enforcer{Owner: owner, Name: name})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.create(tt.source)
			t.Cleanup(func() {
				tt.cleanup(sourceOwner, tt.source)
				tt.cleanup(targetOwner, tt.target)
			})

			_, _ = tt.update(tt.source, tt.target)

			sourceExists, err := tt.get(sourceOwner, tt.source)
			if err != nil {
				t.Fatal(err)
			}
			targetExists, err := tt.get(targetOwner, tt.target)
			if err != nil {
				t.Fatal(err)
			}
			if !sourceExists || targetExists {
				t.Fatalf("%s update moved %s/%s to %s/%s; source_exists=%t target_exists=%t", tt.name, sourceOwner, tt.source, targetOwner, tt.target, sourceExists, targetExists)
			}
		})
	}
}

func newOwnerUpdatePermission(owner string, name string) *Permission {
	return &Permission{
		Owner:     owner,
		Name:      name,
		Users:     []string{owner + "/alice"},
		Resources: []string{"data1"},
		Actions:   []string{"read"},
		Effect:    "Allow",
		IsEnabled: true,
	}
}

func mustTestAction(t *testing.T, affected bool, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
	if !affected {
		t.Fatal("expected setup write to affect one row")
	}
}
