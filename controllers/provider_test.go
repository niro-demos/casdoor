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

func TestGetProviderAuthorizesFetchedProviderBeforeResponding(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "provider.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	getProvider := findFuncDecl(file, "GetProvider")
	if getProvider == nil {
		t.Fatal("GetProvider was not found")
	}

	objectGetProvider := -1
	requireProviderPermission := -1
	responseOk := -1
	ast.Inspect(getProvider.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		switch {
		case isSelectorCall(call, "object", "GetProvider"):
			objectGetProvider = fileSet.Position(call.Pos()).Offset
		case isSelectorCall(call, "c", "requireProviderPermission"):
			requireProviderPermission = fileSet.Position(call.Pos()).Offset
		case isSelectorCall(call, "c", "ResponseOk"):
			responseOk = fileSet.Position(call.Pos()).Offset
		}
		return true
	})

	if objectGetProvider == -1 {
		t.Fatal("GetProvider does not fetch a provider")
	}
	if requireProviderPermission == -1 {
		t.Fatal("GetProvider must authorize the fetched provider before returning it")
	}
	if responseOk == -1 {
		t.Fatal("GetProvider does not return a successful response")
	}
	if !(objectGetProvider < requireProviderPermission && requireProviderPermission < responseOk) {
		t.Fatalf("GetProvider must authorize the fetched provider after loading it and before ResponseOk; offsets: get=%d require=%d response=%d", objectGetProvider, requireProviderPermission, responseOk)
	}
}

func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if ok && funcDecl.Name.Name == name {
			return funcDecl
		}
	}
	return nil
}

func isSelectorCall(call *ast.CallExpr, receiverName string, selectorName string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != selectorName {
		return false
	}

	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == receiverName
}
