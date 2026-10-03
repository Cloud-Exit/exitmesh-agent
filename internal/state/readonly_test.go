package state

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

var writeVerbs = map[string]bool{
	"Create": true, "CreateToken": true, "Update": true, "UpdateStatus": true, "UpdateScale": true, "Delete": true,
	"DeleteCollection": true, "Patch": true, "Apply": true, "ApplyStatus": true, "ApplyScale": true, "Evict": true,
	"EvictV1": true, "EvictV1beta1": true, "Bind": true, "ProxyGet": true, "Stream": true,
}

var forbiddenResources = map[string]bool{
	"selfsubjectaccessreviews": true, "subjectaccessreviews": true, "selfsubjectrulesreviews": true,
	"tokenreviews": true, "localsubjectaccessreviews": true, "exec": true, "attach": true, "portforward": true, "proxy": true,
}

func TestPackageNeverWritesToKubernetes(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || !writeVerbs[sel.Sel.Name] {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "protocol" {
					return true
				}
				t.Errorf("%s: call to %s", fset.Position(x.Pos()), sel.Sel.Name)
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					if s, err := strconv.Unquote(x.Value); err == nil && forbiddenResources[s] {
						t.Errorf("%s: forbidden resource literal %q", fset.Position(x.Pos()), s)
					}
				}
			}
			return true
		})
	}
	if checked < 8 {
		t.Fatalf("only %d source files checked", checked)
	}
}
