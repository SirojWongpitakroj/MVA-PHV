package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// A deployable application needs an entry point before its initialization can
// be tested through the executable.
func TestMainHasEntryPoint(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == "main" &&
			function.Type.Params.NumFields() == 0 && function.Type.Results == nil {
			return
		}
	}
	t.Fatal("main.go has no func main; application initialization is not wired yet")
}
