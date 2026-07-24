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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestGetSubscriptionEnforcesSessionOwnership(t *testing.T) {
	source, err := os.ReadFile("subscription.go")
	if err != nil {
		t.Fatal(err)
	}

	file, err := parser.ParseFile(token.NewFileSet(), "subscription.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}

	var body string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "GetSubscription" {
			continue
		}
		body = string(source[fn.Body.Pos()-1 : fn.Body.End()-1])
	}
	if body == "" {
		t.Fatal("GetSubscription handler not found")
	}

	required := map[string]string{
		"admin bypass":           "c.IsAdmin()",
		"session user lookup":    "c.GetSessionUsername()",
		"subscription ownership": "subscription.User",
		"deny response":          "c.ResponseError(c.T(\"auth:Unauthorized operation\"))",
	}

	for name, needle := range required {
		if !strings.Contains(body, needle) {
			t.Fatalf("GetSubscription does not enforce %s before returning subscription details", name)
		}
	}
}
