package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The manual is what an agent reads before its first call, so it is pinned to
// the code: every tool name and every error code declared in this package must
// appear in usage.md. The constants are collected from the source rather than
// from a hand-kept list, so a constant added later cannot be forgotten here.

// codePackages is every package under internal/ — every package that may
// declare an error code an agent can see. It is discovered rather than listed:
// cve-lookup named its upstream client's directory by hand, and a list kept by
// hand is a promise ("every code is documented") that goes quietly false the
// day a package is added or renamed.
func codePackages(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatalf("read internal/: %v", err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join("..", e.Name()))
		}
	}
	if len(dirs) < 4 {
		t.Fatalf("found only %v under internal/ — the walk is broken", dirs)
	}
	return dirs
}

// declaredConstants returns the string value of every package-level constant
// whose name starts with prefix, across dirs, keyed as "<dir>:<name>".
func declaredConstants(t *testing.T, prefix string, dirs ...string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]string{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read package dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			collectConstants(t, fset, dir, name, prefix, out)
		}
	}
	return out
}

func collectConstants(t *testing.T, fset *token.FileSet, dir, name, prefix string, out map[string]string) {
	t.Helper()
	file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filepath.Join(dir, name), err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if !strings.HasPrefix(ident.Name, prefix) || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", ident.Name, err)
				}
				out[dir+":"+ident.Name] = val
			}
		}
	}
}

func TestManualDocumentsEveryTool(t *testing.T) {
	tools := declaredConstants(t, "Tool", ".")
	if len(tools) == 0 {
		t.Fatal("found no Tool* constants — the collector is broken")
	}
	listed := map[string]bool{}
	for _, def := range toolDefinitions() {
		name, _ := def["name"].(string)
		listed[name] = true
	}
	for constName, tool := range tools {
		if !strings.Contains(UsageDoc(), "### "+tool+"\n") {
			t.Errorf("%s (%q) has no section in usage.md", constName, tool)
		}
		if !listed[tool] {
			t.Errorf("%s (%q) is declared but not in tools/list", constName, tool)
		}
	}
	for tool := range listed {
		found := false
		for _, v := range tools {
			found = found || v == tool
		}
		if !found {
			t.Errorf("tools/list names %q, which has no Tool* constant", tool)
		}
	}
}

func TestManualDocumentsEveryErrorCode(t *testing.T) {
	codes := declaredConstants(t, "Code", codePackages(t)...)
	if len(codes) == 0 {
		t.Fatal("found no Code* constants — the collector is broken")
	}
	for constName, code := range codes {
		if !strings.Contains(UsageDoc(), "| `"+code+"` |") {
			t.Errorf("%s (%q) has no row in the usage.md error table", constName, code)
		}
	}
}

// Every argument a tool's inputSchema declares, and every value of an enum, must
// be named in the manual — in that tool's own section. Searching the whole
// document would let an argument documented under one tool vouch for the same
// name under every other.
func TestManualDocumentsEveryArgument(t *testing.T) {
	for _, def := range toolDefinitions() {
		name, _ := def["name"].(string)
		section := toolSection(UsageDoc(), name)
		if section == "" {
			t.Errorf("tool %s has no \"### %s\" section in usage.md", name, name)
			continue
		}
		schema, _ := def["inputSchema"].(map[string]any)
		props, _ := schema["properties"].(map[string]any)
		for arg, spec := range props {
			if !strings.Contains(section, "`"+arg+"`") {
				t.Errorf("tool %s: argument %q is not documented in its section of usage.md", name, arg)
			}
			values, _ := spec.(map[string]any)["enum"].([]string)
			for _, v := range values {
				if !strings.Contains(section, "`"+v+"`") {
					t.Errorf("tool %s: value %q of %q is not documented in its section of usage.md", name, v, arg)
				}
			}
		}
	}
	if toolSection("\n### a\nbody a\n### b\nbody b\n## Errors\n", "b") != "body b" {
		t.Error("toolSection does not stop at the next heading")
	}
}

// toolSection is the text under "### name", up to the next heading.
func toolSection(doc, name string) string {
	_, after, ok := strings.Cut(doc, "\n### "+name+"\n")
	if !ok {
		return ""
	}
	for _, next := range []string{"\n### ", "\n## "} {
		if i := strings.Index(after, next); i >= 0 {
			after = after[:i]
		}
	}
	return strings.TrimSpace(after)
}

// The "not implemented yet" sentence is guarded in both directions. While the
// lookup tools are missing the manual has to say so — an agent that reads a
// tool list it cannot call wastes its first turn finding that out. Once they
// land the sentence has to go: a status line guarded only while it is true
// outlives the day it becomes false.
func TestNotImplementedStatementMatchesTheToolList(t *testing.T) {
	readme := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(raw)
	}
	scaffold := len(toolDefinitions()) <= 2
	for where, doc := range map[string]struct{ text, marker string }{
		"usage.md":                {UsageDoc(), "not implemented yet"},
		"initialize instructions": {instructions, "not implemented yet"},
		"README.md":               {readme("README.md"), "the lookup tools arrive with"},
		"README.ja.md":            {readme("README.ja.md"), "照会ツールはエンジンと共に入ります"},
	} {
		says := strings.Contains(doc.text, doc.marker)
		switch {
		case scaffold && !says:
			t.Errorf("%s does not say that the lookup tools are missing (%q)", where, doc.marker)
		case !scaffold && says:
			t.Errorf("%s still says the lookup tools are missing (%q), but tools/list has %d tools", where, doc.marker, len(toolDefinitions()))
		}
	}
}
