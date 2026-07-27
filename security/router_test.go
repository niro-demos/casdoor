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

package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestLogoutRouteRejectsCrossSiteGetNavigation(t *testing.T) {
	methods := getRouteMethods(t, "../routers/router.go", "/api/logout")

	if strings.Contains(methods, "GET") {
		t.Fatalf("/api/logout must not accept GET because cross-site top-level navigation can carry the session cookie; got %q", methods)
	}
	if !strings.Contains(methods, "POST") {
		t.Fatalf("/api/logout must keep first-party POST logout support; got %q", methods)
	}
}

func getRouteMethods(t *testing.T, filename string, route string) string {
	t.Helper()

	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var methods string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}

		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Router" {
			return true
		}

		path, ok := call.Args[0].(*ast.BasicLit)
		if !ok || strings.Trim(path.Value, `"`) != route {
			return true
		}

		mapping, ok := call.Args[2].(*ast.BasicLit)
		if !ok {
			t.Fatalf("route %s uses a non-literal method mapping", route)
		}
		methods = strings.Trim(mapping.Value, `"`)
		return false
	})

	if methods == "" {
		t.Fatalf("route %s is not registered", route)
	}
	return methods
}
