package controllers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

func TestCasbinMaintenanceEndpointsRequireGlobalAdmin(t *testing.T) {
	tests := []struct {
		file     string
		function string
	}{
		{file: "casbin_cli_api.go", function: "RunCasbinCommand"},
		{file: "cli_downloader.go", function: "RefreshEngines"},
	}

	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			path := filepath.Join(".", tt.file)
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			var function *ast.FuncDecl
			for _, decl := range parsed.Decls {
				candidate, ok := decl.(*ast.FuncDecl)
				if ok && candidate.Name.Name == tt.function {
					function = candidate
					break
				}
			}
			if function == nil {
				t.Fatalf("function %s not found", tt.function)
			}

			calls := map[string]int{}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if ok {
					calls[selector.Sel.Name]++
				}
				return true
			})

			if calls["IsGlobalAdmin"] == 0 {
				t.Errorf("%s does not enforce the global-administrator invariant", tt.function)
			}
			if calls["IsAdmin"] != 0 {
				t.Errorf("%s uses organization-inclusive IsAdmin for instance-wide maintenance", tt.function)
			}
		})
	}
}
