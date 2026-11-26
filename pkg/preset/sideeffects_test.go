package preset

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// maxLabel is the most runes a side effect's label may have: the terminal
// report puts it before the lead on the same line.
const maxLabel = 22

// problem is one place where a side effect's words break the rule.
type problem struct {
	pos token.Position
	msg string
}

func (p problem) String() string { return fmt.Sprintf("%s: %s", p.pos, p.msg) }

// modelPath is the import path of the package that declares SideEffect.
const modelPath = "github.com/ProdMask/ProdMask/pkg/model"

// checkSideEffects reads parsed source files and returns the places where a
// side effect's words break the rule the reports rely on: every
// model.SideEffect literal sets Label to a string literal of 1 to maxLabel
// runes, and Lead to a variable that Summary is or begins with, the first
// operand of its + chain, so the terminal's lead is the start of the
// sentence every other output shows. A side effect is handed to the scan
// only as such a literal, and nothing writes to a Summary or a Lead
// afterwards, by assignment, through a pointer or as a range variable,
// which could make them part.
func checkSideEffects(fset *token.FileSet, files []*ast.File) []problem {
	var out []problem
	report := func(n ast.Node, format string, a ...any) {
		out = append(out, problem{fset.Position(n.Pos()), fmt.Sprintf(format, a...)})
	}
	written := func(n ast.Node, e ast.Expr) {
		if sel, ok := e.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Summary" || sel.Sel.Name == "Lead") {
			report(n, "%s is written after the side effect is built", sel.Sel.Name)
		}
	}
	for _, f := range files {
		model := modelName(f)
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				switch {
				case isSideEffect(n.Type, model):
					checkLiteral(n, report)
				case holdsSideEffects(n.Type, model):
					// Elements whose type the literal leaves out.
					for _, el := range n.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok {
							el = kv.Value
						}
						if lit, ok := el.(*ast.CompositeLit); ok && lit.Type == nil {
							checkLiteral(lit, report)
						}
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					written(n, lhs)
				}
			case *ast.RangeStmt:
				written(n, n.Key)
				written(n, n.Value)
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					written(n, n.X)
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "sideEffect" {
					if len(n.Args) != 1 || !isSideEffectLit(n.Args[0], model) {
						report(n, "sideEffect is given something other than a model.SideEffect literal")
					}
				}
			}
			return true
		})
	}
	return out
}

// modelName is the name a file imports the model package under, or "" when
// it doesn't import it.
func modelName(f *ast.File) string {
	for _, imp := range f.Imports {
		if path, err := strconv.Unquote(imp.Path.Value); err == nil && path == modelPath {
			if imp.Name != nil {
				return imp.Name.Name
			}
			return "model"
		}
	}
	return ""
}

// isSideEffect reports a type written <model>.SideEffect, with the name the
// file imports the model package under.
func isSideEffect(e ast.Expr, model string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "SideEffect" || model == "" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == model
}

// holdsSideEffects reports a slice, array or map type of side effects,
// whose literal can leave its elements' type out.
func holdsSideEffects(e ast.Expr, model string) bool {
	switch t := e.(type) {
	case *ast.ArrayType:
		return isSideEffect(t.Elt, model)
	case *ast.MapType:
		return isSideEffect(t.Value, model)
	}
	return false
}

func isSideEffectLit(e ast.Expr, model string) bool {
	lit, ok := e.(*ast.CompositeLit)
	return ok && isSideEffect(lit.Type, model)
}

func checkLiteral(lit *ast.CompositeLit, report func(ast.Node, string, ...any)) {
	fields := map[string]ast.Expr{}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			report(el, "a model.SideEffect literal without field names")
			return
		}
		if key, ok := kv.Key.(*ast.Ident); ok {
			fields[key.Name] = kv.Value
		}
	}
	switch label, ok := fields["Label"].(*ast.BasicLit); {
	case !ok || label.Kind != token.STRING:
		report(lit, "Label isn't a string literal")
	default:
		s, err := strconv.Unquote(label.Value)
		if n := utf8.RuneCountInString(s); err != nil || n == 0 || n > maxLabel {
			report(label, "Label %s has %d runes; it needs 1 to %d", label.Value, n, maxLabel)
		}
	}
	lead, ok := fields["Lead"].(*ast.Ident)
	if !ok {
		report(lit, "Lead isn't a variable")
		return
	}
	summary := fields["Summary"]
	for {
		bin, ok := summary.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			break
		}
		summary = bin.X
	}
	if first, ok := summary.(*ast.Ident); !ok || first.Name != lead.Name {
		report(lit, "Summary doesn't begin with Lead's variable %s", lead.Name)
	}
}

// parseDir parses the package's own source files, not its tests.
func parseDir(t *testing.T, dir string) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no Go files in %s", dir)
	}
	return fset, files
}

// TestSideEffectWords checks every side effect pkg/preset builds, reading
// the package's own source files.
func TestSideEffectWords(t *testing.T) {
	fset, files := parseDir(t, ".")
	literals := 0
	for _, f := range files {
		model := modelName(f)
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.CompositeLit); ok && isSideEffect(lit.Type, model) {
				literals++
			}
			return true
		})
	}
	// The 18 checks each build one; fewer means the parse missed some.
	if literals < 18 {
		t.Errorf("found %d model.SideEffect literals; the checks build 18", literals)
	}
	for _, p := range checkSideEffects(fset, files) {
		t.Error(p)
	}
}

// TestCheckSideEffects feeds the checker sources held in memory: each bad
// one must give a problem, and the good ones none.
func TestCheckSideEffects(t *testing.T) {
	const head = "package p\n\nimport \"" + modelPath + "\"\n\nfunc f(n int) {\n"
	cases := []struct {
		name, body string
		bad        bool
	}{
		{"a sentence that is all lead", `lead := "Email is on"
	e.sideEffect(model.SideEffect{Label: "send email", Lead: lead, Summary: lead})`, false},
		{"a lead and a rest", `lead, a, b := "x", "; y", " (z)"
	use(model.SideEffect{Label: "run cron jobs", Lead: lead, Summary: lead + a + b})`, false},
		{"a label of 22 runes", `lead := "x"
	use(model.SideEffect{Label: "` + strings.Repeat("é", 22) + `", Lead: lead, Summary: lead})`, false},
		{"elements whose type a slice leaves out", `xs := []model.SideEffect{{Kind: "email", Summary: "x"}}
	use(xs)`, true},
		{"elements whose type a map leaves out", `m := map[string]model.SideEffect{"a": {Kind: "email", Summary: "x"}}
	use(m)`, true},
		{"a summary written through a pointer", `lead := "x"
	s := model.SideEffect{Label: "send email", Lead: lead, Summary: lead}
	p := &s.Summary
	*p = "y"
	use(s)`, true},
		{"a lead written as a range variable", `lead := "x"
	s := model.SideEffect{Label: "send email", Lead: lead, Summary: lead}
	for _, s.Lead = range []string{"y"} {
	}
	use(s)`, true},
		{"a side effect handed over as a variable", `lead := "x"
	s := model.SideEffect{Label: "send email", Lead: lead, Summary: lead}
	e.sideEffect(s)`, true},
		{"a summary that doesn't begin with its lead", `lead, rest := "x", "y"
	use(model.SideEffect{Label: "send email", Lead: lead, Summary: rest + lead})`, true},
		{"a summary of another variable", `lead, other := "x", "y"
	use(model.SideEffect{Label: "send email", Lead: lead, Summary: other})`, true},
		{"no label", `lead := "x"
	use(model.SideEffect{Lead: lead, Summary: lead})`, true},
		{"an empty label", `lead := "x"
	use(model.SideEffect{Label: "", Lead: lead, Summary: lead})`, true},
		{"a label of 23 runes", `lead := "x"
	use(model.SideEffect{Label: "` + strings.Repeat("é", 23) + `", Lead: lead, Summary: lead})`, true},
		{"a label that isn't a literal", `lead, label := "x", "send email"
	use(model.SideEffect{Label: label, Lead: lead, Summary: lead})`, true},
		{"a lead that isn't a variable", `use(model.SideEffect{Label: "send email", Lead: "x", Summary: "x"})`, true},
		{"a summary assigned later", `lead := "x"
	s := model.SideEffect{Label: "send email", Lead: lead, Summary: lead}
	s.Summary += "y"
	use(s)`, true},
		{"a lead assigned later", `lead := "x"
	s := model.SideEffect{Label: "send email", Lead: lead, Summary: lead}
	s.Lead = "y"
	use(s)`, true},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, c.name+".go", head+"\t"+c.body+"\n}\n", 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := checkSideEffects(fset, []*ast.File{f})
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: got problems %v; want bad %v", c.name, got, c.bad)
		}
	}
	// A file that imports the model package under another name.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "alias.go", "package p\n\nimport m \""+modelPath+"\"\n\nfunc f() {\n"+
		"\te.sideEffect(m.SideEffect{Kind: \"email\", Summary: \"x\"})\n}\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := checkSideEffects(fset, []*ast.File{f}); len(got) == 0 {
		t.Error("a literal without a label passed under an aliased import")
	}
}
