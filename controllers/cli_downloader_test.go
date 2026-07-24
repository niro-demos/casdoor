package controllers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestRefreshEnginesRequiresGlobalAdmin(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "cli_downloader.go", nil, 0)
	if err != nil {
		t.Fatalf("parse cli_downloader.go: %v", err)
	}

	refreshEngines := findFuncDecl(file, "RefreshEngines")
	if refreshEngines == nil {
		t.Fatal("RefreshEngines was not found")
	}

	var callsIsGlobalAdmin bool
	var callsIsAdmin bool
	ast.Inspect(refreshEngines.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		switch selector.Sel.Name {
		case "IsGlobalAdmin":
			callsIsGlobalAdmin = true
		case "IsAdmin":
			callsIsAdmin = true
		}

		return true
	})

	if !callsIsGlobalAdmin {
		t.Fatal("RefreshEngines must require IsGlobalAdmin before server-wide engine refresh")
	}
	if callsIsAdmin {
		t.Fatal("RefreshEngines must not authorize organization administrators with IsAdmin")
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
