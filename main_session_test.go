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

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestMainConfiguresSecureSessionTransportGuard(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("failed to parse main.go: %v", err)
	}

	if !hasAssignment(file, "web.BConfig.WebConfig.Session.SessionName", `"casdoor_session_id"`) {
		t.Fatal("main must keep the browser session cookie name set to casdoor_session_id")
	}

	if !hasFilterRegistration(file, "routers.SessionTransportFilter") {
		t.Fatal("main must register SessionTransportFilter so authenticated sessions are not accepted over plaintext HTTP")
	}
}

func hasAssignment(file *ast.File, leftName string, rightValue string) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if found {
			return false
		}

		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}

		for i, lhs := range assign.Lhs {
			if exprName(lhs) != leftName || i >= len(assign.Rhs) {
				continue
			}
			if exprName(assign.Rhs[i]) == rightValue {
				found = true
				return false
			}
		}

		return true
	})
	return found
}

func hasFilterRegistration(file *ast.File, filterName string) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if found {
			return false
		}

		call, ok := node.(*ast.CallExpr)
		if !ok || exprName(call.Fun) != "web.InsertFilter" {
			return true
		}
		for _, arg := range call.Args {
			if exprName(arg) == filterName {
				found = true
				return false
			}
		}

		return true
	})
	return found
}

func exprName(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.BasicLit:
		return node.Value
	case *ast.Ident:
		return node.Name
	case *ast.SelectorExpr:
		return exprName(node.X) + "." + node.Sel.Name
	default:
		return ""
	}
}
