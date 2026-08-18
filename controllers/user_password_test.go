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
	"testing"
)

func TestSetPasswordRevokesTargetUserSessions(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "user.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	wanted := map[string]bool{
		"ExpireTokenByUser":     false,
		"GetUserSessions":       false,
		"DeleteBeegoSession":    false,
		"DeleteAllUserSessions": false,
	}
	insideSetPassword := false
	ast.Inspect(file, func(node ast.Node) bool {
		if declaration, ok := node.(*ast.FuncDecl); ok {
			insideSetPassword = declaration.Name.Name == "SetPassword"
		}
		if !insideSetPassword {
			return true
		}

		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, required := wanted[selector.Sel.Name]; required {
			wanted[selector.Sel.Name] = true
		}
		return true
	})

	for call, found := range wanted {
		if !found {
			t.Errorf("SetPassword does not call object.%s for the target account", call)
		}
	}
}
