package transform

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/lukaszraczylo/go-obfuscation/pkg/strenc"
	"github.com/lukaszraczylo/go-obfuscation/pkg/stringcrypt"
	"github.com/lukaszraczylo/go-obfuscation/pkg/vm"
)

type Config struct {
	EncryptStrings      bool
	InjectOpaquePreds   bool
	InjectDeadCode      bool
	RandomizeOrder      bool
	IndirectDispatch    bool
	BogusControlFlow    bool
	FlattenControl      bool
	SpliceCode          bool
	BuildSeed           int64
	InjectBuildID       bool
	VirtualizeFunctions bool
	AntiDisassembly     bool
	JunkStrings         bool
	ConstantBlind       bool
	ApplyMBA            bool
	FakeSignatures      bool
	FunctionSplit       bool
	ReorderBasicBlocks  bool
}

func DefaultConfig() Config {
	return Config{
		EncryptStrings:      true,
		InjectOpaquePreds:   true,
		InjectDeadCode:      true,
		RandomizeOrder:      true,
		IndirectDispatch:    true,
		BogusControlFlow:    true,
		FlattenControl:      true,
		SpliceCode:          true,
		InjectBuildID:       true,
		VirtualizeFunctions: true,
		AntiDisassembly:     true,
		JunkStrings:         true,
		ConstantBlind:       true,
		ApplyMBA:            true,
		FakeSignatures:      true,
		FunctionSplit:       true,
		ReorderBasicBlocks:  true,
	}
}

type Transformer struct {
	config Config
	rng    *rand.Rand
}

func New(config Config) *Transformer {
	return &Transformer{
		config: config,
		rng:    rand.New(rand.NewSource(config.BuildSeed)),
	}
}

type stringReplacement struct {
	start    int
	end      int
	replExpr string
}

func (t *Transformer) TransformFile(srcPath, dstPath string) error {
	src, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcPath, err)
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, srcPath, src, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse %s: %w", srcPath, err)
	}

	result := string(src)

	if t.config.EncryptStrings {
		result, err = t.transformStrings(fset, f, result)
		if err != nil {
			return fmt.Errorf("encrypt strings %s: %w", srcPath, err)
		}
		result = convertConstToVar(result)
		result = SplitLongStrings(result)
	}

	if t.config.InjectOpaquePreds {
		result = t.injectOpaquePredicates(result)
	}

	if t.config.InjectDeadCode {
		result = t.injectDeadCode(result)
	}

	if t.config.BogusControlFlow {
		result = t.injectBogusControlFlow(result)
	}

	if t.config.IndirectDispatch {
		result = t.indirectDispatch(result)
	}

	if t.config.SpliceCode {
		result = t.spliceCode(result)
	}

	if t.config.FlattenControl {
		result = t.flattenSimpleFunctions(result)
	}

	if t.config.FunctionSplit {
		result = SplitFunctions(result)
	}

	if t.config.ReorderBasicBlocks {
		result = ReorderBasicBlocks(result)
	}

	if t.config.ConstantBlind {
		result = TransformConstants(result)
	}

	if t.config.ApplyMBA {
		result = TransformMBA(result)
	}

	if t.config.FakeSignatures {
		result = InjectFakeSignatures(result)
	}

	if t.config.InjectBuildID && strings.HasSuffix(srcPath, "main.go") {
		result = t.injectBuildID(result)
	}

	if t.config.VirtualizeFunctions {
		result = t.virtualizeFunctions(result)
	}

	if t.config.AntiDisassembly {
		result = t.injectAntiDisassembly(result)
	}

	if t.config.JunkStrings {
		result = t.injectJunkStrings(result)
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dstPath), err)
	}

	if err := os.WriteFile(dstPath, []byte(result), 0644); err != nil {
		return fmt.Errorf("write %s: %w", dstPath, err)
	}

	return nil
}

func (t *Transformer) TransformDir(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("readdir %s: %w", srcDir, err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		if entry.IsDir() {
			if err := t.TransformDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".go") {
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(dstDir, 0755); err != nil {
				return err
			}
			if err := os.WriteFile(dstPath, data, 0644); err != nil {
				return err
			}
			continue
		}

		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		fmt.Printf("  transforming: %s\n", entry.Name())
		if err := t.TransformFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("transform %s: %w", srcPath, err)
		}
	}

	return nil
}

func (t *Transformer) transformStrings(fset *token.FileSet, f *ast.File, src string) (string, error) {
	type repl struct {
		start int
		end   int
		expr  string
	}

	importRanges := map[int]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		imp, ok := n.(*ast.ImportSpec)
		if !ok {
			return true
		}
		if imp.Path != nil {
			start := fset.Position(imp.Path.Pos()).Offset
			end := fset.Position(imp.Path.End()).Offset
			for i := start; i < end; i++ {
				importRanges[i] = true
			}
		}
		return true
	})

	var replacements []repl
	var plaintexts []string

	ast.Inspect(f, func(n ast.Node) bool {
		basicLit, ok := n.(*ast.BasicLit)
		if !ok || basicLit.Kind != token.STRING {
			return true
		}

		startOff := fset.Position(basicLit.Pos()).Offset
		if importRanges[startOff] {
			return true
		}

		raw := basicLit.Value
		if len(raw) < 4 {
			return true
		}

		var unquoted string
		if raw[0] == '"' && raw[len(raw)-1] == '"' {
			var err error
			unquoted, err = unquoteGoString(raw)
			if err != nil || len(unquoted) < 2 {
				return true
			}
		} else {
			return true
		}

		if shouldSkipString(unquoted) {
			return true
		}

		idx := len(plaintexts)
		plaintexts = append(plaintexts, unquoted)

		pos := fset.Position(basicLit.Pos())
		end := fset.Position(basicLit.End())

		replacements = append(replacements, repl{
			start: pos.Offset,
			end:   end.Offset,
			expr:  fmt.Sprintf("_decStr(%d)", idx),
		})

		return true
	})

	if len(replacements) == 0 {
		return src, nil
	}

	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		src = src[:r.start] + r.expr + src[r.end:]
	}

	var seed [32]byte
	if _, err := cryptoRand.Read(seed[:]); err != nil {
		return "", fmt.Errorf("strenc: generate seed: %w", err)
	}
	masterKey := strenc.DeriveMasterKey(seed)

	var entries []strenc.Entry
	const padBlock = 64
	for _, pt := range plaintexts {
		ptBytes := []byte(pt)
		ptLen := len(ptBytes)

		padded := make([]byte, 2+ptLen)
		padded[0] = byte(ptLen & 0xFF)
		padded[1] = byte((ptLen >> 8) & 0xFF)
		copy(padded[2:], ptBytes)

		if len(padded)%padBlock != 0 {
			targetLen := ((len(padded) / padBlock) + 1) * padBlock
			paddedBuf := make([]byte, targetLen)
			copy(paddedBuf, padded)
			cryptoRand.Read(paddedBuf[len(padded):])
			padded = paddedBuf
		}

		var iv [16]byte
		if _, err := cryptoRand.Read(iv[:]); err != nil {
			return "", fmt.Errorf("strenc: generate iv: %w", err)
		}

		mac := hmac.New(sha256.New, masterKey[:])
		mac.Write(iv[:])
		var subkey [32]byte
		copy(subkey[:], mac.Sum(nil))

		entry := encryptEntryGCM(string(padded), subkey, iv)
		entries = append(entries, entry)
	}

	var poolCode strings.Builder
	poolCode.WriteString("\nvar _masterSeed = [32]byte{")
	for i, b := range seed {
		if i > 0 {
			poolCode.WriteString(", ")
		}
		fmt.Fprintf(&poolCode, "0x%02X", b)
	}
	poolCode.WriteString("}\n")
	poolCode.WriteString("var _encEntries = []strenc.Entry{\n")
	for _, e := range entries {
		poolCode.WriteString("\t{Ciphertext: []byte{")
		for i, b := range e.Ciphertext {
			if i > 0 {
				poolCode.WriteString(", ")
			}
			fmt.Fprintf(&poolCode, "0x%02X", b)
		}
		poolCode.WriteString("}, IV: [16]byte{")
		for i, b := range e.IV {
			if i > 0 {
				poolCode.WriteString(", ")
			}
			fmt.Fprintf(&poolCode, "0x%02X", b)
		}
		poolCode.WriteString("}},\n")
	}
	poolCode.WriteString("}\n")
	poolCode.WriteString("var _encPool = strenc.NewPool(_masterSeed, _encEntries)\n")
	poolCode.WriteString("//go:noinline\nfunc _decStr(i int) string { _b := []byte(_encPool.GetString(i)); if len(_b) < 2 { return \"\" }; _n := int(_b[0]) | int(_b[1])<<8; if _n > len(_b)-2 { return \"\" }; return string(_b[2:2+_n]) }\n")

	insertAt := findImportBlockEnd(src)
	if insertAt == -1 {
		pkgIdx := strings.Index(src, "package ")
		if pkgIdx != -1 {
			lineEnd := strings.Index(src[pkgIdx:], "\n")
			if lineEnd != -1 {
				insertAt = pkgIdx + lineEnd + 1
			}
		}
	}
	if insertAt != -1 && insertAt < len(src) {
		src = src[:insertAt] + poolCode.String() + src[insertAt:]
	}

	src = t.ensureImport(src, "github.com/lukaszraczylo/go-obfuscation/pkg/strenc")

	return src, nil
}

func encryptEntryGCM(plaintext string, key [32]byte, iv [16]byte) strenc.Entry {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(fmt.Sprintf("transform: aes.NewCipher: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("transform: cipher.NewGCM: %v", err))
	}
	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	copy(nonce, iv[:nonceSize])
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return strenc.Entry{Ciphertext: ct, IV: iv}
}

func writeHexLiteral(sb *strings.Builder, data []byte) {
	sb.WriteString("[]byte{")
	for i, b := range data {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(sb, "0x%02X", b)
	}
	sb.WriteString("}")
}

func findImportBlockEnd(src string) int {
	idx := strings.Index(src, "import (")
	if idx != -1 {
		rest := src[idx+len("import ("):]
		depth := 1
		for i, c := range rest {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					return idx + len("import (") + i + 1
				}
			}
		}
		return -1
	}

	idx = strings.Index(src, "import \"")
	if idx != -1 {
		lineEnd := strings.Index(src[idx:], "\n")
		if lineEnd != -1 {
			return idx + lineEnd + 1
		}
		return len(src)
	}

	return -1
}

func shouldSkipString(s string) bool {
	skipPrefixes := []string{
		"go:", "//", "+build", "package", "go:", "module",
		"//go:", "// +build",
	}
	for _, p := range skipPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	if len(s) == 0 {
		return true
	}
	if s[0] == '/' || s[0] == '+' {
		return true
	}
	return false
}

func unquoteGoString(s string) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("not a quoted string")
	}
	s = s[1 : len(s)-1]

	var result strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				result.WriteByte('\n')
				i++
			case 't':
				result.WriteByte('\t')
				i++
			case 'r':
				result.WriteByte('\r')
				i++
			case '\\':
				result.WriteByte('\\')
				i++
			case '"':
				result.WriteByte('"')
				i++
			default:
				result.WriteByte(s[i])
			}
		} else {
			result.WriteByte(s[i])
		}
	}
	return result.String(), nil
}

func (t *Transformer) injectOpaquePredicates(src string) string {
	lines := strings.Split(src, "\n")
	var result []string
	inFuncBody := false
	funcStmtCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "func ") && strings.HasSuffix(trimmed, "{") {
			inFuncBody = true
			funcStmtCount = 0
			result = append(result, line)
			continue
		}

		if inFuncBody && trimmed == "}" {
			inFuncBody = false
			result = append(result, line)
			continue
		}

		if inFuncBody && strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t") && trimmed != "" {
			funcStmtCount++
			if funcStmtCount >= 3 && t.rng.Float64() < 0.4 {
				result = append(result, "\t"+"if func() bool { return "+t.generateTrueExpression()+" }() { _ = struct{}{} }")
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

func (t *Transformer) injectDeadCode(src string) string {
	lines := strings.Split(src, "\n")
	var result []string
	inFuncBody := false
	funcStmtCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "func ") && strings.HasSuffix(trimmed, "{") {
			inFuncBody = true
			funcStmtCount = 0
			result = append(result, line)
			continue
		}

		if inFuncBody && trimmed == "}" {
			inFuncBody = false
			result = append(result, line)
			continue
		}

		if inFuncBody && strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t") && trimmed != "" {
			funcStmtCount++
			if funcStmtCount >= 3 && t.rng.Float64() < 0.3 {
				result = append(result, "\t"+"if func() bool { return "+t.generateFalseExpression()+" }() { println(\"unreachable\") }")
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

func isValidIdent(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, c := range s {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func getIndent(line string) string {
	indent := ""
	for _, c := range line {
		if c == ' ' || c == '\t' {
			indent += string(c)
		} else {
			break
		}
	}
	return indent
}

func convertConstToVar(src string) string {
	lines := strings.Split(src, "\n")
	inConstBlock := false
	hasEncrypted := false
	constStartLines := []int{}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "const (" {
			inConstBlock = true
			hasEncrypted = false
			constStartLines = append(constStartLines, i)
			continue
		}
		if inConstBlock && trimmed == ")" {
			if hasEncrypted {
				lines[constStartLines[len(constStartLines)-1]] = strings.Replace(
					lines[constStartLines[len(constStartLines)-1]], "const (", "var (", 1,
				)
			}
			inConstBlock = false
			continue
		}
		if inConstBlock && (strings.Contains(line, "base64.StdEncoding.DecodeString") || strings.Contains(line, "_decStr(")) {
			hasEncrypted = true
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "const ") && (strings.Contains(line, "base64.StdEncoding.DecodeString") || strings.Contains(line, "_decStr(")) {
			lines[i] = strings.Replace(line, "const ", "var ", 1)
		}
	}

	return strings.Join(lines, "\n")
}

func replaceInLines(lines []string, old, new string) []string {
	var result []string
	for _, l := range lines {
		result = append(result, strings.Replace(l, old, new, 1))
	}
	return result
}

func (t *Transformer) RandomizeOrder(f *ast.File) {
	if len(f.Decls) <= 1 {
		return
	}

	t.rng.Shuffle(len(f.Decls), func(i, j int) {
		f.Decls[i], f.Decls[j] = f.Decls[j], f.Decls[i]
	})
}

func (t *Transformer) injectBogusControlFlow(src string) string {
	lines := strings.Split(src, "\n")
	var result []string
	inFuncBody := false
	stmtCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "func ") && strings.HasSuffix(trimmed, "{") {
			inFuncBody = true
			stmtCount = 0
			result = append(result, line)
			continue
		}

		if inFuncBody && trimmed == "}" {
			inFuncBody = false
			result = append(result, line)
			continue
		}

		if inFuncBody && strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t") && trimmed != "" {
			stmtCount++
			if stmtCount >= 2 && t.rng.Float64() < 0.25 {
				result = append(result, t.generateBogusBranch())
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

func (t *Transformer) generateBogusBranch() string {
	n := t.rng.Intn(4)
	switch n {
	case 0:
		v := stringcrypt.RandomIdent("_bc", 5)
		return fmt.Sprintf(
			"\tif func() bool { %s := int64(1); for i := 0; i < 10; i++ { %s = %s*7%%49999999 }; return %s == 1 }() { _ = struct{}{} }",
			v, v, v, v,
		)
	case 1:
		v := stringcrypt.RandomIdent("_bc", 5)
		a := t.rng.Intn(100) + 1
		return fmt.Sprintf(
			"\tif func() bool { %s := %d*%d; return %s%%2 == 0 && %s > 0 }() { _ = struct{}{} }",
			v, a, a, v, v,
		)
	case 2:
		v := stringcrypt.RandomIdent("_bc", 5)
		return fmt.Sprintf(
			"\tif func() bool { %s := [4]byte{0x72, 0x6F, 0x6F, 0x74}; return len(%s) == 4 }() { _ = struct{}{} }",
			v, v,
		)
	default:
		v := stringcrypt.RandomIdent("_bc", 5)
		return fmt.Sprintf(
			"\t{ %s := func() int { n := 0; for i := 1; i <= 100; i++ { n += i }; return n }(); _ = %s }",
			v, v,
		)
	}
}

func (t *Transformer) flattenSimpleFunctions(src string) string {
	lines := strings.Split(src, "\n")
	var result []string
	i := 0

	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])

		if strings.HasPrefix(trimmed, "func ") && strings.HasSuffix(trimmed, "{") && !strings.Contains(trimmed, "main") && !strings.Contains(trimmed, "init()") {
			funcLines := []string{lines[i]}
			i++
			depth := 1
			for i < len(lines) && depth > 0 {
				for _, c := range lines[i] {
					if c == '{' {
						depth++
					}
					if c == '}' {
						depth--
					}
				}
				funcLines = append(funcLines, lines[i])
				i++
			}

			if len(funcLines) > 5 && t.rng.Float64() < 0.4 {
				flattened := flattenFunctionBody(funcLines)
				result = append(result, flattened...)
			} else {
				result = append(result, funcLines...)
			}
			continue
		}

		result = append(result, lines[i])
		i++
	}

	return strings.Join(result, "\n")
}

func flattenFunctionBody(funcLines []string) []string {
	funcSig := funcLines[0]
	bodyLines := funcLines[1 : len(funcLines)-1]
	closingBrace := funcLines[len(funcLines)-1]

	if len(bodyLines) < 3 {
		return funcLines
	}

	var statements [][]string
	var current []string
	depth := 0

	for _, l := range bodyLines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}

		for _, c := range l {
			if c == '{' {
				depth++
			}
			if c == '}' {
				depth--
			}
		}

		current = append(current, l)

		if depth <= 0 && trimmed != "{" {
			statements = append(statements, current)
			current = nil
			depth = 0
		}
	}

	if len(current) > 0 {
		statements = append(statements, current)
	}

	if len(statements) < 3 {
		return funcLines
	}

	for _, stmt := range statements {
		for _, line := range stmt {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, ":=") {
				parts := strings.SplitN(trimmed, ":=", 2)
				varName := strings.TrimSpace(parts[0])
				if isValidIdent(varName) && !strings.Contains(varName, ",") {
					rhs := strings.TrimSpace(parts[1])
					if inferTypeFromRHS(rhs) == "" {
						return funcLines
					}
				}
			}
		}
	}

	var result []string
	result = append(result, funcSig)

	var hoistedVars []string
	declaredVars := map[string]bool{}
	for idx, stmt := range statements {
		for _, line := range stmt {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, ":=") {
				parts := strings.SplitN(trimmed, ":=", 2)
				varName := strings.TrimSpace(parts[0])
				if !isValidIdent(varName) && !strings.Contains(varName, ",") {
					continue
				}
				rhs := strings.TrimSpace(parts[1])
				if !strings.Contains(varName, ",") {
					typ := inferTypeFromRHS(rhs)
					if typ == "" {
						continue
					}
					if !declaredVars[varName] {
						hoistedVars = append(hoistedVars, "\tvar "+varName+" "+typ)
						declaredVars[varName] = true
					}
					statements[idx] = replaceInLines(statements[idx], varName+" :=", varName+" =")
				} else {
					names := strings.Split(varName, ",")
					allValid := true
					for _, n := range names {
						n = strings.TrimSpace(n)
						if n != "" && !isValidIdent(n) {
							allValid = false
							break
						}
					}
					if !allValid {
						continue
					}
					for _, n := range names {
						n = strings.TrimSpace(n)
						if n != "" && !declaredVars[n] {
							hoistedVars = append(hoistedVars, "\tvar "+n+" int")
							declaredVars[n] = true
						}
					}
					statements[idx] = replaceInLines(statements[idx], varName+" :=", varName+" =")
				}
			}
		}
	}
	for _, v := range hoistedVars {
		result = append(result, v)
	}

	stateVar := stringcrypt.RandomIdent("_st", 4)
	result = append(result, "\t"+stateVar+" := 0")
	result = append(result, "\tfor {")
	result = append(result, "\t\tswitch "+stateVar+" {")

	numStates := len(statements)
	for idx, stmt := range statements {
		result = append(result, fmt.Sprintf("\t\tcase %d:", idx))
		for _, line := range stmt {
			result = append(result, "\t\t"+strings.TrimPrefix(line, "\t"))
		}
		if idx < numStates-1 {
			result = append(result, fmt.Sprintf("\t\t\t%s = %d", stateVar, idx+1))
		} else {
			result = append(result, "\t\t\treturn")
		}
	}

	result = append(result, "\t\tdefault:")
	result = append(result, "\t\t\treturn")
	result = append(result, "\t\t}")
	result = append(result, "\t}")
	result = append(result, closingBrace)

	return result
}

func (t *Transformer) generateTrueExpression() string {
	a := t.rng.Intn(1000) + 1
	switch t.rng.Intn(6) {
	case 0:
		return fmt.Sprintf("%d%%%d == 0", a*7, 7)
	case 1:
		return fmt.Sprintf("(%d^%d) == 0", a, a)
	case 2:
		return fmt.Sprintf("^(%d|%d) == ^%d", a, a, a)
	case 3:
		return fmt.Sprintf("(%d & %d) == %d", a, a, a)
	case 4:
		return fmt.Sprintf("len([%d]byte{}) == 0", t.rng.Intn(8)+1)
	default:
		b := t.rng.Intn(100) + 1
		return fmt.Sprintf("(%d+%d) > %d", b, a, b+a-1)
	}
}

func (t *Transformer) generateFalseExpression() string {
	a := t.rng.Intn(0xFFFF) + 1
	switch t.rng.Intn(6) {
	case 0:
		return fmt.Sprintf("(%d - %d) < 0", a, a)
	case 1:
		return fmt.Sprintf("func() bool { return 1 < 0 }()")
	case 2:
		return fmt.Sprintf("func() bool { var _x = %d; return _x > _x }()", a)
	case 3:
		return fmt.Sprintf("func() bool { var _x int = %d; _x -= %d; return _x > 0 }()", a, a)
	case 4:
		return fmt.Sprintf("len([%d]byte{}) < 0", t.rng.Intn(8)+1)
	default:
		return fmt.Sprintf("func() bool { return (%d^%d) > 0 && (%d^%d) < 0 }()", a, a, a, a)
	}
}

func (t *Transformer) injectBuildID(src string) string {
	buildID := fmt.Sprintf("BUILD_%d_%08X", t.config.BuildSeed, t.rng.Int31())
	decl := fmt.Sprintf("\nvar _buildID = %q // polymorphic build marker\nvar _ = _buildID\n", buildID)

	insertAfter := findImportBlockEnd(src)

	if insertAfter == -1 {
		pkgIdx := strings.Index(src, "package ")
		if pkgIdx == -1 {
			return src
		}
		lineEnd := strings.Index(src[pkgIdx:], "\n")
		if lineEnd == -1 {
			return src + decl
		}
		insertAfter = pkgIdx + lineEnd
	}

	return src[:insertAfter+1] + decl + src[insertAfter+1:]
}

func (t *Transformer) indirectDispatch(src string) string {
	lines := strings.Split(src, "\n")
	var result []string
	var wrappers []string
	dispatchIdx := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmed, "func ") || !strings.HasSuffix(trimmed, "{") {
			result = append(result, line)
			continue
		}

		parenIdx := strings.Index(trimmed, "(")
		if parenIdx == -1 {
			result = append(result, line)
			continue
		}

		funcName := strings.TrimSpace(trimmed[5:parenIdx])

		if funcName == "main" || funcName == "init" || funcName == "" || strings.ToUpper(funcName[:1]) == funcName[:1] || strings.HasPrefix(funcName, "_") {
			result = append(result, line)
			continue
		}

		obfSuffix := fmt.Sprintf("_obf%d", t.rng.Intn(9000)+1000)

		renameFrom := "func " + funcName + "("
		renameTo := "func " + funcName + obfSuffix + "("
		renamedLine := strings.Replace(line, renameFrom, renameTo, 1)
		result = append(result, renamedLine)

		restOfSig := trimmed[parenIdx:]
		sigClean := strings.TrimSuffix(restOfSig, " {")

		depth := 0
		paramsEnd := -1
		for i, c := range sigClean {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					paramsEnd = i
					break
				}
			}
		}

		if paramsEnd == -1 {
			continue
		}

		params := sigClean[:paramsEnd+1]
		returnType := strings.TrimSpace(sigClean[paramsEnd+1:])
		hasReturn := returnType != ""

		argsStart := strings.Index(params, "(") + 1
		argsEnd := strings.LastIndex(params, ")")
		argStr := params[argsStart:argsEnd]
		argNames := extractArgNames(argStr)
		callArgs := strings.Join(argNames, ", ")

		ptrVar := fmt.Sprintf("_fptr%d", dispatchIdx)
		dispatchIdx++

		if hasReturn {
			ptrDecl := fmt.Sprintf("var %s = %s", ptrVar, funcName+obfSuffix)
			wrappers = append(wrappers, ptrDecl)
			wrapperFunc := fmt.Sprintf("//go:noinline\nfunc %s%s %s { return %s(%s) }",
				funcName, params, returnType, ptrVar, callArgs)
			wrappers = append(wrappers, wrapperFunc)
		} else {
			ptrDecl := fmt.Sprintf("var %s = %s", ptrVar, funcName+obfSuffix)
			wrappers = append(wrappers, ptrDecl)
			wrapperFunc := fmt.Sprintf("//go:noinline\nfunc %s%s { %s(%s) }",
				funcName, params, ptrVar, callArgs)
			wrappers = append(wrappers, wrapperFunc)
		}
	}

	if len(wrappers) > 0 {
		insertAt := -1
		inImportBlock := false
		for i, line := range result {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "import") && strings.Contains(t, "(") {
				inImportBlock = true
				continue
			}
			if inImportBlock && t == ")" {
				insertAt = i + 1
				break
			}
		}
		if insertAt == -1 {
			for i, line := range result {
				if strings.HasPrefix(strings.TrimSpace(line), "package ") {
					insertAt = i + 1
					break
				}
			}
		}
		if insertAt >= 0 {
			for insertAt < len(result) && strings.TrimSpace(result[insertAt]) == "" {
				insertAt++
			}
			newResult := make([]string, 0, len(result)+len(wrappers)+1)
			newResult = append(newResult, result[:insertAt]...)
			newResult = append(newResult, "")
			newResult = append(newResult, wrappers...)
			newResult = append(newResult, result[insertAt:]...)
			result = newResult
		}
	}

	return strings.Join(result, "\n")
}

func extractArgNames(argStr string) []string {
	if strings.TrimSpace(argStr) == "" {
		return nil
	}
	var names []string
	for _, arg := range strings.Split(argStr, ",") {
		arg = strings.TrimSpace(arg)
		parts := strings.Fields(arg)
		if len(parts) >= 2 {
			names = append(names, parts[0])
		} else if len(parts) == 1 {
			names = append(names, parts[0])
		}
	}
	return names
}

func (t *Transformer) spliceCode(src string) string {
	lines := strings.Split(src, "\n")
	var result []string
	i := 0

	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])

		if strings.HasPrefix(trimmed, "func ") && strings.HasSuffix(trimmed, "{") &&
			!strings.Contains(trimmed, "main") && !strings.Contains(trimmed, "init") &&
			!strings.Contains(trimmed, "func()") {

			funcSig := lines[i]
			i++
			depth := 1
			var bodyLines []string
			for i < len(lines) && depth > 0 {
				for _, c := range lines[i] {
					if c == '{' {
						depth++
					}
					if c == '}' {
						depth--
					}
				}
				if depth > 0 {
					bodyLines = append(bodyLines, lines[i])
				}
				i++
			}

			simpleStmts := 0
			hasControlFlow := false
			for _, bl := range bodyLines {
				bt := strings.TrimSpace(bl)
				if bt == "" || bt == "{" || bt == "}" {
					continue
				}
				if strings.HasPrefix(bt, "if ") || strings.HasPrefix(bt, "for ") ||
					strings.HasPrefix(bt, "switch ") || strings.HasPrefix(bt, "select ") ||
					strings.HasPrefix(bt, "case ") || strings.HasPrefix(bt, "default:") {
					hasControlFlow = true
					break
				}
				if strings.HasPrefix(bt, "return ") || strings.HasPrefix(bt, "return") {
					break
				}
				simpleStmts++
			}

			if simpleStmts >= 5 && !hasControlFlow && t.rng.Float64() < 0.5 {
				spliced := t.buildSplicedFunction(funcSig, bodyLines)
				result = append(result, spliced...)
			} else {
				result = append(result, funcSig)
				result = append(result, bodyLines...)
				result = append(result, "}")
			}
			continue
		}

		result = append(result, lines[i])
		i++
	}

	return strings.Join(result, "\n")
}

func (t *Transformer) buildSplicedFunction(funcSig string, bodyLines []string) []string {
	var result []string
	result = append(result, funcSig)

	var stmts []string
	var hoistedVars []string
	declaredVars := map[string]bool{}
	for _, line := range bodyLines {
		bt := strings.TrimSpace(line)
		if bt == "" || bt == "{" || bt == "}" {
			continue
		}
		if strings.Contains(bt, ":=") {
			parts := strings.SplitN(bt, ":=", 2)
			varName := strings.TrimSpace(parts[0])
			if !isValidIdent(varName) && !strings.Contains(varName, ",") {
				stmts = append(stmts, bt)
				continue
			}
			rhs := strings.TrimSpace(parts[1])
			if !strings.Contains(varName, ",") {
				typ := inferTypeFromRHS(rhs)
				if typ == "" {
					stmts = append(stmts, bt)
					continue
				}
				if !declaredVars[varName] {
					hoistedVars = append(hoistedVars, "\tvar "+varName+" "+typ)
					declaredVars[varName] = true
				}
				bt = varName + " = " + rhs
			} else {
				names := strings.Split(varName, ",")
				allValid := true
				for _, n := range names {
					n = strings.TrimSpace(n)
					if n != "" && !isValidIdent(n) {
						allValid = false
						break
					}
				}
				if !allValid {
					stmts = append(stmts, bt)
					continue
				}
				for _, n := range names {
					n = strings.TrimSpace(n)
					if n != "" && !declaredVars[n] {
						hoistedVars = append(hoistedVars, "\tvar "+n+" int")
						declaredVars[n] = true
					}
				}
				bt = varName + " = " + rhs
			}
		}
		stmts = append(stmts, bt)
	}

	for _, v := range hoistedVars {
		result = append(result, v)
	}

	stateVar := stringcrypt.RandomIdent("_sp", 4)
	result = append(result, "\t"+stateVar+" := 0")

	returnVar := ""
	lastStmt := strings.TrimSpace(stmts[len(stmts)-1])
	if strings.HasPrefix(lastStmt, "return ") {
		returnExpr := strings.TrimPrefix(lastStmt, "return ")
		returnVar = stringcrypt.RandomIdent("_ret", 4)
		result = append(result, "\tvar "+returnVar+" "+inferTypeFromRHS(returnExpr))
		stmts[len(stmts)-1] = returnVar + " = " + returnExpr
	}

	result = append(result, "\tfor {")
	result = append(result, "\t\tswitch "+stateVar+" {")

	numFragments := 2
	if len(stmts) > 7 {
		numFragments = 3
	}
	fragmentSize := len(stmts) / numFragments

	fragIdx := 0
	for f := 0; f < numFragments; f++ {
		result = append(result, fmt.Sprintf("\t\tcase %d:", f))
		end := (f + 1) * fragmentSize
		if f == numFragments-1 {
			end = len(stmts)
		}
		for j := f * fragmentSize; j < end; j++ {
			result = append(result, "\t\t\t"+stmts[j])
		}
		if f < numFragments-1 {
			result = append(result, fmt.Sprintf("\t\t\t%s = %d", stateVar, f+1))
		} else {
			if returnVar != "" {
				result = append(result, "\t\t\treturn "+returnVar)
			} else {
				result = append(result, "\t\t\treturn")
			}
		}
		fragIdx++
	}

	result = append(result, "\t\tdefault:")
	if returnVar != "" {
		result = append(result, "\t\t\treturn "+returnVar)
	} else {
		result = append(result, "\t\t\treturn")
	}
	result = append(result, "\t\t}")
	result = append(result, "\t}")
	result = append(result, "}")

	return result
}

func inferTypeFromRHS(rhs string) string {
	rhs = strings.TrimSpace(rhs)
	if strings.HasPrefix(rhs, "\"") || strings.HasPrefix(rhs, "`") {
		return "string"
	}
	if strings.HasPrefix(rhs, "fmt.Sprintf") || strings.HasPrefix(rhs, "func() string") {
		return "string"
	}
	if strings.HasPrefix(rhs, "[]byte") || strings.HasPrefix(rhs, "make([]byte") {
		return "[]byte"
	}
	if rhs == "true" || rhs == "false" {
		return "bool"
	}
	if strings.Contains(rhs, "sha256.Sum256") {
		return "[32]byte"
	}
	return ""
}

var vmLenPattern = regexp.MustCompile(`(?m)^func\s+(\w+)\((\w+)\s+string\)\s+bool\s*\{\s*\n\s*return\s+len\((\w+)\)\s*>\s*(\d+)\s*\n\s*\}`)

var vmLenEqPattern = regexp.MustCompile(`(?m)^func\s+(\w+)\((\w+)\s+string\)\s+bool\s*\{\s*\n\s*return\s+len\((\w+)\)\s*==\s*(\d+)\s*\n\s*\}`)

var vmLenLtPattern = regexp.MustCompile(`(?m)^func\s+(\w+)\((\w+)\s+string\)\s+bool\s*\{\s*\n\s*return\s+len\((\w+)\)\s*<\s*(\d+)\s*\n\s*\}`)

var vmLenGePattern = regexp.MustCompile(`(?m)^func\s+(\w+)\((\w+)\s+string\)\s+bool\s*\{\s*\n\s*return\s+len\((\w+)\)\s*>=\s*(\d+)\s*\n\s*\}`)

var vmArith2Pattern = regexp.MustCompile(`(?m)^func\s+(\w+)\((\w+),\s*(\w+)\s+(?:int|int64)\)\s+(?:int|int64)\s*\{\s*\n\s*return\s+(\w+)\s*([+\-*/%^&|])\s*(\w+)\s*\n\s*\}`)

var vmArith1Pattern = regexp.MustCompile(`(?m)^func\s+(\w+)\((\w+)\s+(?:int|int64)\)\s+(?:int|int64)\s*\{\s*\n\s*return\s+(\w+)\s*([+\-*/%^&|])\s*(\d+)\s*\n\s*\}`)

func (t *Transformer) virtualizeFunctions(src string) string {
	type replacement struct {
		start int
		end   int
		text  string
	}

	var repls []replacement

	for _, loc := range vmLenPattern.FindAllStringIndex(src, -1) {
		full := src[loc[0]:loc[1]]
		sub := vmLenPattern.FindStringSubmatch(full)
		if len(sub) >= 5 && sub[2] == sub[3] {
			n, _ := strconv.ParseInt(sub[4], 10, 64)
			bc := compileLenCmpBytecode("gt", n)
			repls = append(repls, replacement{loc[0], loc[1], buildVMBoolFunc(sub[1], sub[2], bc)})
		}
	}
	for _, loc := range vmLenEqPattern.FindAllStringIndex(src, -1) {
		full := src[loc[0]:loc[1]]
		sub := vmLenEqPattern.FindStringSubmatch(full)
		if len(sub) >= 5 && sub[2] == sub[3] {
			n, _ := strconv.ParseInt(sub[4], 10, 64)
			bc := compileLenCmpBytecode("eq", n)
			repls = append(repls, replacement{loc[0], loc[1], buildVMBoolFunc(sub[1], sub[2], bc)})
		}
	}
	for _, loc := range vmLenLtPattern.FindAllStringIndex(src, -1) {
		full := src[loc[0]:loc[1]]
		sub := vmLenLtPattern.FindStringSubmatch(full)
		if len(sub) >= 5 && sub[2] == sub[3] {
			n, _ := strconv.ParseInt(sub[4], 10, 64)
			bc := compileLenCmpBytecode("lt", n)
			repls = append(repls, replacement{loc[0], loc[1], buildVMBoolFunc(sub[1], sub[2], bc)})
		}
	}
	for _, loc := range vmLenGePattern.FindAllStringIndex(src, -1) {
		full := src[loc[0]:loc[1]]
		sub := vmLenGePattern.FindStringSubmatch(full)
		if len(sub) >= 5 && sub[2] == sub[3] {
			n, _ := strconv.ParseInt(sub[4], 10, 64)
			bc := compileLenCmpBytecode("ge", n)
			repls = append(repls, replacement{loc[0], loc[1], buildVMBoolFunc(sub[1], sub[2], bc)})
		}
	}

	for _, loc := range vmArith2Pattern.FindAllStringIndex(src, -1) {
		full := src[loc[0]:loc[1]]
		sub := vmArith2Pattern.FindStringSubmatch(full)
		if len(sub) >= 7 {
			funcName, p1, p2, left, op, right := sub[1], sub[2], sub[3], sub[4], sub[5], sub[6]
			if left == p1 && right == p2 {
				bc := compileArith2Bytecode(op, 0, 1)
				repls = append(repls, replacement{loc[0], loc[1], buildVMIntFunc2(funcName, p1, p2, bc)})
			} else if left == p2 && right == p1 {
				bc := compileArith2Bytecode(op, 1, 0)
				repls = append(repls, replacement{loc[0], loc[1], buildVMIntFunc2(funcName, p1, p2, bc)})
			}
		}
	}

	for _, loc := range vmArith1Pattern.FindAllStringIndex(src, -1) {
		full := src[loc[0]:loc[1]]
		sub := vmArith1Pattern.FindStringSubmatch(full)
		if len(sub) >= 6 {
			funcName, param, left, op, nStr := sub[1], sub[2], sub[3], sub[4], sub[5]
			if left == param {
				n, _ := strconv.ParseInt(nStr, 10, 64)
				bc := compileArith1Bytecode(op, n)
				repls = append(repls, replacement{loc[0], loc[1], buildVMIntFunc1(funcName, param, bc)})
			}
		}
	}

	if len(repls) == 0 {
		return src
	}

	for i := len(repls) - 1; i >= 0; i-- {
		r := repls[i]
		src = src[:r.start] + r.text + src[r.end:]
	}

	if !strings.Contains(src, "\"github.com/lukaszraczylo/go-obfuscation/pkg/vm\"") {
		src = t.ensureImport(src, "github.com/lukaszraczylo/go-obfuscation/pkg/vm")
	}

	return src
}

func compileLenCmpBytecode(op string, n int64) []byte {
	var bc []byte
	bc = append(bc, vm.EncodeInstr(vm.OpPush, 0)...)
	bc = append(bc, vm.EncodeInstr(vm.OpCall, 0)...)
	bc = append(bc, vm.EncodeInstr(vm.OpPush, n)...)
	switch op {
	case "gt":
		bc = append(bc, vm.EncodeInstr(vm.OpCmpGt, 0)...)
	case "eq":
		bc = append(bc, vm.EncodeInstr(vm.OpCmpEq, 0)...)
	case "lt":
		bc = append(bc, vm.EncodeInstr(vm.OpCmpLt, 0)...)
	case "ge":
		bc = append(bc, vm.EncodeInstr(vm.OpCmpLt, 0)...)
		bc = append(bc, vm.EncodeInstr(vm.OpPush, 0)...)
		bc = append(bc, vm.EncodeInstr(vm.OpCmpEq, 0)...)
	}
	bc = append(bc, vm.EncodeInstr(vm.OpHalt, 0)...)
	return bc
}

func compileArith2Bytecode(op string, leftID, rightID int64) []byte {
	var bc []byte
	bc = append(bc, vm.EncodeInstr(vm.OpPush, 0)...)       // arity=0
	bc = append(bc, vm.EncodeInstr(vm.OpCall, leftID)...)  // get left param
	bc = append(bc, vm.EncodeInstr(vm.OpPush, 0)...)       // arity=0
	bc = append(bc, vm.EncodeInstr(vm.OpCall, rightID)...) // get right param
	switch op {
	case "+":
		bc = append(bc, vm.EncodeInstr(vm.OpAdd, 0)...)
	case "-":
		bc = append(bc, vm.EncodeInstr(vm.OpSub, 0)...)
	case "*":
		bc = append(bc, vm.EncodeInstr(vm.OpMul, 0)...)
	case "/":
		bc = append(bc, vm.EncodeInstr(vm.OpDiv, 0)...)
	case "%":
		bc = append(bc, vm.EncodeInstr(vm.OpMod, 0)...)
	case "^":
		bc = append(bc, vm.EncodeInstr(vm.OpXor, 0)...)
	case "&":
		bc = append(bc, vm.EncodeInstr(vm.OpAnd, 0)...)
	case "|":
		bc = append(bc, vm.EncodeInstr(vm.OpOr, 0)...)
	}
	bc = append(bc, vm.EncodeInstr(vm.OpHalt, 0)...)
	return bc
}

func compileArith1Bytecode(op string, n int64) []byte {
	var bc []byte
	bc = append(bc, vm.EncodeInstr(vm.OpPush, 0)...) // arity=0
	bc = append(bc, vm.EncodeInstr(vm.OpCall, 0)...) // get param
	bc = append(bc, vm.EncodeInstr(vm.OpPush, n)...) // constant
	switch op {
	case "+":
		bc = append(bc, vm.EncodeInstr(vm.OpAdd, 0)...)
	case "-":
		bc = append(bc, vm.EncodeInstr(vm.OpSub, 0)...)
	case "*":
		bc = append(bc, vm.EncodeInstr(vm.OpMul, 0)...)
	case "/":
		bc = append(bc, vm.EncodeInstr(vm.OpDiv, 0)...)
	case "%":
		bc = append(bc, vm.EncodeInstr(vm.OpMod, 0)...)
	case "^":
		bc = append(bc, vm.EncodeInstr(vm.OpXor, 0)...)
	case "&":
		bc = append(bc, vm.EncodeInstr(vm.OpAnd, 0)...)
	case "|":
		bc = append(bc, vm.EncodeInstr(vm.OpOr, 0)...)
	}
	bc = append(bc, vm.EncodeInstr(vm.OpHalt, 0)...)
	return bc
}

func buildVMBoolFunc(funcName, paramName string, bc []byte) string {
	var byteLits []string
	for _, b := range bc {
		byteLits = append(byteLits, fmt.Sprintf("0x%02X", b))
	}
	return fmt.Sprintf(`//go:noinline
func %s(%s string) bool {
	_co := map[int]func([]int64) int64{
		0: func(_ []int64) int64 { return int64(len(%s)) },
	}
	_bc := []byte{%s}
	_vm := vm.NewVM(_bc, _co)
	return _vm.Run() != 0
}`, funcName, paramName, paramName, strings.Join(byteLits, ", "))
}

func buildVMIntFunc2(funcName, p1, p2 string, bc []byte) string {
	var byteLits []string
	for _, b := range bc {
		byteLits = append(byteLits, fmt.Sprintf("0x%02X", b))
	}
	return fmt.Sprintf(`//go:noinline
func %s(%s, %s int64) int64 {
	_co := map[int]func([]int64) int64{
		0: func(_ []int64) int64 { return %s },
		1: func(_ []int64) int64 { return %s },
	}
	_bc := []byte{%s}
	_vm := vm.NewVM(_bc, _co)
	return _vm.Run()
}`, funcName, p1, p2, p1, p2, strings.Join(byteLits, ", "))
}

func buildVMIntFunc1(funcName, param string, bc []byte) string {
	var byteLits []string
	for _, b := range bc {
		byteLits = append(byteLits, fmt.Sprintf("0x%02X", b))
	}
	return fmt.Sprintf(`//go:noinline
func %s(%s int64) int64 {
	_co := map[int]func([]int64) int64{
		0: func(_ []int64) int64 { return %s },
	}
	_bc := []byte{%s}
	_vm := vm.NewVM(_bc, _co)
	return _vm.Run()
}`, funcName, param, param, strings.Join(byteLits, ", "))
}

func (t *Transformer) injectAntiDisassembly(src string) string {
	lines := strings.Split(src, "\n")
	var result []string
	inFuncBody := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "func ") && strings.HasSuffix(trimmed, "{") {
			inFuncBody = true
			result = append(result, line)
			continue
		}

		if inFuncBody && trimmed == "}" {
			inFuncBody = false
			result = append(result, line)
			continue
		}

		if inFuncBody && strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t") && trimmed != "" {
			if t.rng.Float64() < 0.15 {
				junkVar := stringcrypt.RandomIdent("_ad", 4)
				junkSize := t.rng.Intn(32) + 8
				result = append(result, fmt.Sprintf("\tvar %s [%d]byte; _ = %s", junkVar, junkSize, junkVar))
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

func (t *Transformer) injectJunkStrings(src string) string {
	junkStrings := []string{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789abcdef0123456789abcdef",
		"/usr/lib/libSystem.B.dylib",
		"/proc/self/maps",
		"\\x00\\x00\\x00\\x00",
		"HKEY_LOCAL_MACHINE\\SOFTWARE",
		"C:\\Windows\\System32\\ntdll.dll",
		"SELECT * FROM users WHERE id=?",
		"Content-Type: application/json",
		"Mozilla/5.0 (Windows NT 10.0)",
		"-----BEGIN RSA PRIVATE KEY-----",
		"192.168.1.1:8080",
		"admin@localhost",
		"Bearer eyJhbGciOiJIUzI1NiJ9",
		"application/x-www-form-urlencoded",
	}

	numJunk := t.rng.Intn(6) + 4
	var junkBlock strings.Builder
	junkBlock.WriteString("\nvar _junkData = [...]string{\n")
	for i := 0; i < numJunk; i++ {
		idx := t.rng.Intn(len(junkStrings))
		junkBlock.WriteString(fmt.Sprintf("\t%q,\n", junkStrings[idx]))
	}
	junkBlock.WriteString("}\n")
	junkBlock.WriteString("var _ = _junkData\n")

	insertAt := findImportBlockEnd(src)
	if insertAt == -1 {
		pkgIdx := strings.Index(src, "package ")
		if pkgIdx != -1 {
			lineEnd := strings.Index(src[pkgIdx:], "\n")
			if lineEnd != -1 {
				insertAt = pkgIdx + lineEnd + 1
			}
		}
	}
	if insertAt != -1 && insertAt < len(src) {
		src = src[:insertAt] + junkBlock.String() + src[insertAt:]
	}

	return src
}

func (t *Transformer) ensureImport(src string, importPath string) string {
	importBlock := `import ("` + importPath + `")`

	if idx := strings.Index(src, "import ("); idx != -1 {
		insertAt := idx + len("import (")
		return src[:insertAt] + "\n\t\"" + importPath + "\"" + src[insertAt:]
	}

	if idx := strings.Index(src, "import \""); idx != -1 {
		return src[:idx] + importBlock + "\n" + src[idx:]
	}

	pkgEnd := strings.Index(src, "\n\n")
	if pkgEnd == -1 {
		pkgEnd = strings.Index(src, "\n")
	}
	if pkgEnd != -1 {
		return src[:pkgEnd+1] + "\n" + importBlock + "\n" + src[pkgEnd+1:]
	}

	return src
}
