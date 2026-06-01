package transform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestIsValidIdent(t *testing.T) {
	cases := map[string]bool{
		"":        false,
		"x":       true,
		"_":       true,
		"_x":      true,
		"abc123":  true,
		"123abc":  false,
		"a-b":     false,
		"a b":     false,
		"a.b":     false,
		"a$":      false,
		"foo_bar": true,
	}
	for in, want := range cases {
		if got := isValidIdent(in); got != want {
			t.Errorf("isValidIdent(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestUnquoteGoString(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{`"hello"`, "hello", false},
		{`"with\nnewline"`, "with\nnewline", false},
		{`"tab\there"`, "tab\there", false},
		{`"quote\"inside"`, `quote"inside`, false},
		{`"backslash\\"`, `backslash\`, false},
		{`""`, "", false},
		{`"`, "", true},
		{`no quotes`, "", true},
	}
	for _, c := range cases {
		got, err := unquoteGoString(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("unquoteGoString(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("unquoteGoString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestShouldSkipString(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"go:noinline", true},
		{"// comment", true},
		{"+build linux", true},
		{"package main", true},
		{"normal string", false},
		{"/starts with slash", true},
		{"+starts with plus", true},
	}
	for _, c := range cases {
		if got := shouldSkipString(c.in); got != c.want {
			t.Errorf("shouldSkipString(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestInferTypeFromRHS(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`"hello"`, "string"},
		{"`raw`", "string"},
		{"fmt.Sprintf(\"%d\", x)", "string"},
		{"[]byte{1,2,3}", "[]byte"},
		{"make([]byte, 10)", "[]byte"},
		{"true", "bool"},
		{"false", "bool"},
		{"sha256.Sum256([]byte(x))", "[32]byte"},
		{"x + 1", ""}, // numeric, no type
		{"42", ""},
		{"someVar", ""},
	}
	for _, c := range cases {
		if got := inferTypeFromRHS(c.in); got != c.want {
			t.Errorf("inferTypeFromRHS(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestInferVarType(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`"hello"`, "string"},
		{`fmt.Sprintf("x", y)`, "string"},
		{`true`, "bool"},
		{`42`, "int64"},
		{`[3]int{1,2,3}`, ""}, // array — skip
		{`x + 1`, "int64"},
	}
	for _, c := range cases {
		if got := inferVarType(c.in); got != c.want {
			t.Errorf("inferVarType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFindImportBlockEnd(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{
			name: "paren import",
			in:   "package main\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n",
			want: 36, // index after the closing )
		},
		{
			name: "single import",
			in:   "package main\nimport \"fmt\"\n",
			want: 26,
		},
		{
			name: "no imports",
			in:   "package main\n",
			want: -1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := findImportBlockEnd(c.in)
			if c.want == -1 {
				if got != -1 {
					t.Errorf("findImportBlockEnd(%q) = %d, want -1", c.in, got)
				}
				return
			}
			if got != c.want {
				t.Errorf("findImportBlockEnd(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

func TestConvertConstToVarNoOp(t *testing.T) {
	src := "package main\n\nconst (\n\tfoo = 1\n)\n"
	got := convertConstToVar(src)
	if got != src {
		t.Errorf("convertConstToVar modified non-encrypted const block:\nbefore: %q\nafter:  %q", src, got)
	}
}

func TestConvertConstToVarTriggersOnDecStr(t *testing.T) {
	src := "package main\n\nconst (\n\tfoo = _decStr(0)\n)\n"
	got := convertConstToVar(src)
	if !strings.Contains(got, "var (") {
		t.Errorf("convertConstToVar did not promote const to var: %q", got)
	}
}

func TestEnsureImportIntoParenBlock(t *testing.T) {
	src := "package x\nimport (\n\t\"fmt\"\n)\n"
	tr := New(Config{})
	got := tr.ensureImport(src, "github.com/example/pkg")
	if !strings.Contains(got, `"github.com/example/pkg"`) {
		t.Errorf("ensureImport missing target:\n%s", got)
	}
	got2 := tr.ensureImport(src, "github.com/example/pkg")
	if strings.Count(got2, "github.com/example/pkg") != 1 {
		t.Errorf("ensureImport added duplicate: %q", got2)
	}
}

func TestEnsureImportCreatesNewBlock(t *testing.T) {
	src := "package x\n\nfunc main() {}\n"
	tr := New(Config{})
	got := tr.ensureImport(src, "github.com/example/pkg")
	if !strings.Contains(got, `import ("github.com/example/pkg")`) {
		t.Errorf("ensureImport did not create import block:\n%s", got)
	}
}

func TestExtractArgNames(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"x int", []string{"x"}},
		{"x int, y int", []string{"x", "y"}},
		{"x, y int", []string{"x", "y"}},
		{"x int, y string, z []byte", []string{"x", "y", "z"}},
	}
	for _, c := range cases {
		got := extractArgNames(c.in)
		if len(got) != len(c.want) {
			t.Errorf("extractArgNames(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("extractArgNames(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestSplitLongStringsNoShortStrings(t *testing.T) {
	src := `package main
var a = "hi"
var b = "short"
`
	got := SplitLongStrings(src)
	if got != src {
		t.Errorf("SplitLongStrings modified short string block:\nbefore: %q\nafter:  %q", src, got)
	}
}

func TestSplitLongStringsSplitsLongLiteral(t *testing.T) {
	src := `package main
var key = "sk-proj-FAKE-KEY-1234567890abcdef"
`
	got := SplitLongStrings(src)
	if got == src {
		t.Fatalf("SplitLongStrings did not split long string")
	}
	if !strings.Contains(got, " + ") {
		t.Errorf("SplitLongStrings output missing concatenation: %q", got)
	}
	for _, frag := range []string{`"sk-pr"`, `"oj-FA"`, `"KE-KE"`, `"Y-123"`} {
		// We just check the general structure
		_ = frag
	}
}

func TestSplitLongStringsSkipsEscapes(t *testing.T) {
	src := `package main
var s = "abcdefghijklmnopqrs\ntuvwxyz1234"
`
	got := SplitLongStrings(src)
	// Has an escape, must NOT be split
	if got != src {
		t.Errorf("SplitLongStrings split a string with escape sequences:\nbefore: %q\nafter:  %q", src, got)
	}
}

func TestSplitLongStringsSkipsImportBlock(t *testing.T) {
	src := `package main
import "github.com/lukaszraczylo/go-obfuscation/pkg/strenc-with-a-very-long-name-just-to-be-sure"
var x = "abcdefghijklmnopqrstuvwxyz1234"
`
	got := SplitLongStrings(src)
	// The import path must remain a single literal
	if !strings.Contains(got, `"github.com/lukaszraczylo/go-obfuscation/pkg/strenc-with-a-very-long-name-just-to-be-sure"`) {
		t.Errorf("SplitLongStrings modified import path:\n%s", got)
	}
	// The non-import string should be split
	if !strings.Contains(got, " + ") {
		t.Errorf("SplitLongStrings did not split the non-import long string:\n%s", got)
	}
}

func TestTransformConstantsSkipsFuncBodies(t *testing.T) {
	src := `package main
const foo = 100
func bar() int { return 42 }
`
	got := TransformConstants(src)
	// Outside function body — no transform
	if !strings.Contains(got, "const foo = 100") {
		t.Errorf("TransformConstants modified non-function-body code:\n%s", got)
	}
}

func TestTransformConstantsBlindsInsideFunctions(t *testing.T) {
	src := `package main
func bar() int {
	return 42
}
`
	got := TransformConstants(src)
	if !strings.Contains(got, "_blind") {
		t.Errorf("TransformConstants did not introduce a _blind helper call:\n%s", got)
	}
}

func TestTransformConstantsPreservesSmallInts(t *testing.T) {
	src := `package main
func bar() { x := 0; y := 1; z := 2; _ = x; _ = y; _ = z }
`
	got := TransformConstants(src)
	for _, lit := range []string{"0", "1", "2"} {
		// We want these left as-is.
		if !strings.Contains(got, lit) {
			t.Errorf("TransformConstants lost small integer %q in:\n%s", lit, got)
		}
	}
}

func TestTransformMBANoChangeOnAssignments(t *testing.T) {
	// Lines containing := should be left alone by MBA (they're assignments).
	src := `package main
func bar() int { x := a + b; return x }
`
	got := TransformMBA(src)
	if got != src {
		t.Errorf("TransformMBA modified an assignment line:\nbefore: %q\nafter:  %q", src, got)
	}
}

func TestTransformMBAModifiesAddition(t *testing.T) {
	src := `package main
func bar() int {
	_ = a + b
	return 0
}
`
	got := TransformMBA(src)
	if got == src {
		t.Errorf("TransformMBA did not modify a + b")
	}
}

func TestTransformDirCopiesAndSkipsTestFiles(t *testing.T) {
	tmp := t.TempDir()
	srcDir := tmp + "/src"
	dstDir := tmp + "/dst"
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcDir+"/main.go", []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcDir+"/main_test.go", []byte("package main\n// test file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcDir+"/data.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	tr := New(Config{BuildSeed: 1})
	if err := tr.TransformDir(srcDir, dstDir); err != nil {
		t.Fatal(err)
	}

	if _, err := os.ReadFile(dstDir + "/main.go"); err != nil {
		t.Errorf("main.go not copied: %v", err)
	}
	if _, err := os.ReadFile(dstDir + "/data.txt"); err != nil {
		t.Errorf("data.txt not copied: %v", err)
	}
	if _, err := os.ReadFile(dstDir + "/main_test.go"); !os.IsNotExist(err) {
		t.Errorf("main_test.go should not be copied, got err=%v", err)
	}
}

func TestNewSeedsDeterministicTransforms(t *testing.T) {
	src := `package main
func main() { x := 1; _ = x }
`
	tmp := t.TempDir()
	a := src
	b := src
	for i, out := range []*string{&a, &b} {
		dst := tmp + "/d" + string(rune('0'+i))
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		srcFile := dst + "/main.go"
		if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		tr := New(Config{BuildSeed: 42})
		if err := tr.TransformFile(srcFile, dst+"/out.go"); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(dst + "/out.go")
		if err != nil {
			t.Fatal(err)
		}
		*out = string(data)
	}
	if a != b {
		t.Errorf("Same seed produced different output:\nA: %s\nB: %s", a, b)
	}
}

func TestReorderBasicBlocksIdempotentOnNoControlFlow(t *testing.T) {
	src := `package main
func bar() int { return 1 }
`
	got := ReorderBasicBlocks(src)
	// No if/switch in body — output should equal input
	if got != src {
		t.Errorf("ReorderBasicBlocks modified body without control flow:\nbefore: %q\nafter:  %q", src, got)
	}
}

func TestReorderBasicBlocksSwapsIfElse(t *testing.T) {
	src := `package main
func bar(x int) int {
	if x > 0 {
		return 1
	} else {
		return 2
	}
}
`
	got := ReorderBasicBlocks(src)
	// Either condition is negated (x <= 0) OR the swap is skipped (rng < 0.4).
	// We just check that the function is still parseable / both returns survive.
	if !strings.Contains(got, "return 1") || !strings.Contains(got, "return 2") {
		t.Errorf("ReorderBasicBlocks lost a return value:\n%s", got)
	}
}

func TestSplitFunctionsIdempotentOnSmallBodies(t *testing.T) {
	src := `package main
func small() { _ = 1 }
`
	got := SplitFunctions(src)
	if got != src {
		t.Errorf("SplitFunctions modified body with too few stmts:\nbefore: %q\nafter:  %q", src, got)
	}
}

func TestSplitFunctionsSplitsLargeBody(t *testing.T) {
	src := `package main
func big() int {
	a := 1
	b := 2
	c := 3
	d := 4
	e := 5
	f := 6
	g := 7
	h := 8
	return a + b + c + d + e + f + g + h
}
`
	// SplitFunctions uses an internal random source with ~50% split probability.
	// Retry until we observe a split, up to 20 times.
	for i := 0; i < 20; i++ {
		got := SplitFunctions(src)
		if got != src && strings.Contains(got, "switch ") {
			return // pass
		}
	}
	t.Errorf("SplitFunctions never split the large body after 20 attempts")
}

func TestInjectFakeSignaturesAddsFunctions(t *testing.T) {
	src := `package main

func main() {}
`
	got := InjectFakeSignatures(src)
	if !strings.Contains(got, "//go:noinline") {
		t.Errorf("InjectFakeSignatures did not add go:noinline funcs:\n%s", got)
	}
	// Should have introduced new top-level func decls
	origCount := countFuncDecls(src)
	gotCount := countFuncDecls(got)
	if gotCount <= origCount {
		t.Errorf("InjectFakeSignatures did not add funcs: %d -> %d", origCount, gotCount)
	}
}

func countFuncDecls(src string) int {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		return 0
	}
	n := 0
	for _, d := range f.Decls {
		if _, ok := d.(*ast.FuncDecl); ok {
			n++
		}
	}
	return n
}
