// MBA (Mixed Boolean-Arithmetic) expression transformation.
//
// Replaces simple arithmetic and bitwise operations with equivalent
// MBA expressions that produce the same result but obscure the
// original operation from static analysis and decompilation.
package transform

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"

	"github.com/lukaszraczylo/go-obfuscation/pkg/stringcrypt"
)

var (
	// Binary operations: a OP b where OP is +, -, ^, &, |
	// Careful to not match comparison operators (==, !=, <=, >=, <<, >>)
	// and not match unary ^ or -.
	mbaBinAddRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)\s*\+\s*([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)`)
	mbaBinSubRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)\s*-\s*([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)`)
	mbaBinXorRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)\s*\^\s*([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)`)
	mbaBinAndRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)\s*&\s*([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)`)
	mbaBinOrRe  = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)\s*\|\s*([a-zA-Z_][a-zA-Z0-9_.]*|\d+(?:\.\d+)?(?:<<\d+)?)`)

	// Unary bitwise NOT: ^a — match broadly, filter context in replacement
	mbaUnNotRe = regexp.MustCompile(`\^([a-zA-Z_][a-zA-Z0-9_.]*)`)

	// Patterns to skip: comparisons, shifts, assignments
	mbaSkipRe = regexp.MustCompile(`==|!=|<=|>=|<<|>>|<-|\+\+|--|\|\|`)

	// String literal detection to avoid transforming inside strings
	mbaStringLitRe = regexp.MustCompile(`"[^"\\]*(?:\\.[^"\\]*)*"`)
	mbaBacktickRe  = regexp.MustCompile("`[^`]*`")

	// Operators in comparisons, type assertions, channel ops that we must skip
	mbaCtxPatterns = []string{"==", "!=", "<=", ">=", "<<", ">>", "&&", "||", "<-", "++", "--", ":="}
)

// TransformMBA replaces simple arithmetic and bitwise operations with
// equivalent Mixed Boolean-Arithmetic expressions.
func TransformMBA(src string) string {
	rng := rand.New(rand.NewSource(rand.Int63()))

	// Build a set of string-literal and backtick-literal ranges to skip
	skipRanges := buildSkipRanges(src)

	lines := strings.Split(src, "\n")
	var result []string
	inFuncBody := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "func ") && strings.HasSuffix(trimmed, "{") {
			inFuncBody = true
		}
		if inFuncBody && trimmed == "}" {
			inFuncBody = false
		}

		if !inFuncBody || trimmed == "" || strings.HasPrefix(trimmed, "//") {
			result = append(result, line)
			continue
		}

		// Skip lines with comparison/shift operators or assignments
		if containsAny(trimmed, mbaCtxPatterns) {
			result = append(result, line)
			continue
		}

		// Skip lines that are mostly control flow
		if strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "for ") ||
			strings.HasPrefix(trimmed, "switch ") || strings.HasPrefix(trimmed, "return ") ||
			strings.HasPrefix(trimmed, "case ") || strings.HasPrefix(trimmed, "default:") {
			result = append(result, line)
			continue
		}

		lineIdx := len(strings.Join(result, "\n")) + 1
		_ = lineIdx

		transformed := mbaTransformLine(line, rng, skipRanges)
		result = append(result, transformed)
	}

	return strings.Join(result, "\n")
}

func buildSkipRanges(src string) [][2]int {
	var ranges [][2]int
	for _, loc := range mbaStringLitRe.FindAllStringIndex(src, -1) {
		ranges = append(ranges, [2]int{loc[0], loc[1]})
	}
	for _, loc := range mbaBacktickRe.FindAllStringIndex(src, -1) {
		ranges = append(ranges, [2]int{loc[0], loc[1]})
	}
	return ranges
}

func mbaTransformLine(line string, rng *rand.Rand, skipRanges [][2]int) string {
	// Apply transforms in a specific order to avoid double-transforming.
	// We transform the most specific patterns first.

	// First, do unary NOT (most specific)
	line = mbaApplyUnaryNot(line, rng)

	// Then binary ops in order of specificity
	// XOR and AND are more "bitwise" and less likely to be confused
	line = mbaApplyBinOp(line, mbaBinXorRe, mbaXorIdentities, rng)
	line = mbaApplyBinOp(line, mbaBinAndRe, mbaAndIdentities, rng)
	line = mbaApplyBinOp(line, mbaBinOrRe, mbaOrIdentities, rng)
	line = mbaApplyBinOp(line, mbaBinAddRe, mbaAddIdentities, rng)
	line = mbaApplyBinOp(line, mbaBinSubRe, mbaSubIdentities, rng)

	return line
}

type mbaIdentity struct {
	template string
	// If true, this identity introduces ninline helper that must be injected
	hasHelper bool
	helperDef string
}

var mbaAddIdentities = []mbaIdentity{
	{template: "((%s) ^ (%s)) + 2 * ((%s) & (%s))"},
	{template: "((%s) | (%s)) + ((%s) & (%s))"},
	{template: "((%s) ^ (%s)) - ((^(%s)) & (%s)) - ((^(%s)) ^ (%s)) + (^(%s))"},
}

var mbaSubIdentities = []mbaIdentity{
	{template: "((%s) ^ (%s)) - 2 * ((^(%s)) & (%s))"},
	{template: "(%s) + (^(%s)) + 1"},
}

var mbaXorIdentities = []mbaIdentity{
	{template: "((%s) | (%s)) - ((%s) & (%s))"},
	{template: "((%s) & (^(%s))) | ((^(%s)) & (%s))"},
}

var mbaAndIdentities = []mbaIdentity{
	{template: "((%s) | (%s)) - ((%s) ^ (%s))"},
}

var mbaOrIdentities = []mbaIdentity{
	{template: "((%s) ^ (%s)) + ((%s) & (%s))"},
	{template: "((%s) & (%s)) + ((%s) ^ (%s))"},
}

func mbaApplyBinOp(line string, re *regexp.Regexp, identities []mbaIdentity, rng *rand.Rand) string {
	// Use FindAllStringSubmatchIndex so we know the exact position of each match
	// in the line. FindStringIndex on the match alone only gives a position relative
	// to the match, not the line, which previously caused us to mis-attribute
	// already-transformed ranges (the bug: strings.Index(line, match) returns the
	// first occurrence, not the current one).
	type range_ struct{ start, end int }
	var transformed []range_

	// Mutate the line by recording each replacement and applying in a second pass.
	// We can't use ReplaceAllStringFunc alone because we need the absolute position.
	matches := re.FindAllStringSubmatchIndex(line, -1)
	if len(matches) == 0 {
		return line
	}

	type repl struct {
		start, end int
		text       string
	}
	var repls []repl

	for _, loc := range matches {
		fullStart, fullEnd := loc[0], loc[1]
		if fullEnd > len(line) {
			continue
		}
		match := line[fullStart:fullEnd]

		// Overlap with already-transformed region?
		overlap := false
		for _, t := range transformed {
			if fullStart < t.end && fullEnd > t.start {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}

		sub := re.FindStringSubmatch(match)
		if len(sub) < 3 {
			continue
		}
		a, b := sub[1], sub[2]
		if a == "" || b == "" {
			continue
		}
		// Constant-folded by the compiler, no point in transforming.
		if isPureNumeric(a) && isPureNumeric(b) {
			continue
		}

		ident := identities[rng.Intn(len(identities))]
		var result string
		switch len(strings.Split(ident.template, "%s")) - 1 {
		case 2:
			result = fmt.Sprintf(ident.template, a, b)
		case 4:
			result = fmt.Sprintf(ident.template, a, b, a, b)
		case 6:
			result = fmt.Sprintf(ident.template, a, b, a, b, a, b)
		case 7:
			result = fmt.Sprintf(ident.template, a, b, a, b, a, b, a)
		default:
			result = fmt.Sprintf(ident.template, a, b)
		}

		repls = append(repls, repl{start: fullStart, end: fullEnd, text: result})
		transformed = append(transformed, range_{fullStart, fullEnd})
	}

	if len(repls) == 0 {
		return line
	}

	var buf strings.Builder
	buf.Grow(len(line))
	cursor := 0
	for _, r := range repls {
		buf.WriteString(line[cursor:r.start])
		buf.WriteString(r.text)
		cursor = r.end
	}
	buf.WriteString(line[cursor:])
	return buf.String()
}

func mbaApplyUnaryNot(line string, rng *rand.Rand) string {
	// Manual search for ^identifier, checking preceding char
	var buf strings.Builder
	i := 0
	for i < len(line) {
		if line[i] == '^' && i+1 < len(line) {
			// Check it's not preceded by identifier char
			if i > 0 && (isAlphaNum(line[i-1]) || line[i-1] == '_') {
				buf.WriteByte(line[i])
				i++
				continue
			}
			// Check next char starts an identifier
			if !isAlpha(line[i+1]) && line[i+1] != '_' {
				buf.WriteByte(line[i])
				i++
				continue
			}
			// Find end of identifier
			j := i + 1
			for j < len(line) && (isAlphaNum(line[j]) || line[j] == '_' || line[j] == '.') {
				j++
			}
			a := line[i+1 : j]
			if isPureNumeric(a) {
				buf.WriteString(line[i:j])
				i = j
				continue
			}
			switch rng.Intn(3) {
			case 0:
				fmt.Fprintf(&buf, "((-%s) - 1)", a)
			case 1:
				fmt.Fprintf(&buf, "(%s ^ (-1))", a)
			default:
				fmt.Fprintf(&buf, "(%s ^ 0xFFFFFFFFFFFFFFFF)", a)
			}
			i = j
		} else {
			buf.WriteByte(line[i])
			i++
		}
	}
	return buf.String()
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isAlphaNum(b byte) bool {
	return isAlpha(b) || (b >= '0' && b <= '9')
}

func isPureNumeric(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	_, err := strconv.ParseInt(s, 0, 64)
	if err == nil {
		return true
	}
	_, err = strconv.ParseFloat(s, 64)
	return err == nil
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// InjectMBAHelpers inserts the go:noinline wrapper functions needed by MBA
// transformations. Called after all MBA transforms are applied.
func InjectMBAHelpers(src string) string {
	helperName := stringcrypt.RandomIdent("_mba", 5)

	helpers := fmt.Sprintf(`

//go:noinline
func %s_add(a, b int64) int64 { return (a ^ b) + 2*(a&b) }

//go:noinline
func %s_sub(a, b int64) int64 { return (a ^ b) - 2*((^a)&b) }

//go:noinline
func %s_xor(a, b int64) int64 { return (a | b) - (a & b) }

//go:noinline
func %s_and(a, b int64) int64 { return (a | b) - (a ^ b) }

//go:noinline
func %s_or(a, b int64) int64 { return (a ^ b) + (a & b) }

//go:noinline
func %s_not(a int64) int64 { return (-a) - 1 }
`, helperName, helperName, helperName, helperName, helperName, helperName)

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
		src = src[:insertAt] + helpers + src[insertAt:]
	}

	return src
}
