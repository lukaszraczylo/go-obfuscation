// Constant blinding transformation.
//
// Replaces integer literal constants with runtime XOR expressions that
// evaluate to the original value, defeating pattern-matching in disassemblers
// and static analysis tools. Each constant C is replaced with (K ^ (K ^ C))
// where K is a per-constant random key.
package transform

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/lukaszraczylo/go-obfuscation/pkg/stringcrypt"
)

var (
	cbHexRe      = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	cbStringRe   = regexp.MustCompile(`"[^"\\]*(?:\\.[^"\\]*)*"`)
	cbBacktickRe = regexp.MustCompile("`[^`]*`")

	cbSkipContexts = []string{
		"case ", "case\t",
		"[",
		"len(", "cap(",
		"make(",
		"iota",
	}
)

func TransformConstants(src string) string {
	rng := rand.New(rand.NewSource(rand.Int63()))
	blindHelperName := stringcrypt.RandomIdent("_blind", 4)

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

		if !inFuncBody {
			result = append(result, line)
			continue
		}

		if strings.HasPrefix(trimmed, "//") || trimmed == "" || trimmed == "{" || trimmed == "}" {
			result = append(result, line)
			continue
		}

		if shouldCBLineSkip(trimmed) {
			result = append(result, line)
			continue
		}

		blinded := cbBlindLine(line, rng, blindHelperName)
		result = append(result, blinded)
	}

	resultStr := strings.Join(result, "\n")
	resultStr = injectBlindHelper(resultStr, blindHelperName)
	return resultStr
}

func shouldCBLineSkip(trimmed string) bool {
	if strings.HasPrefix(trimmed, "case ") || strings.HasPrefix(trimmed, "case\t") {
		return true
	}
	if strings.Contains(trimmed, "[") && strings.Contains(trimmed, "]") {
		return true
	}
	for _, ctx := range cbSkipContexts {
		if strings.Contains(trimmed, ctx) {
			return true
		}
	}
	return false
}

func cbBlindLine(line string, rng *rand.Rand, helperName string) string {
	line = cbHexRe.ReplaceAllStringFunc(line, func(match string) string {
		return cbBlindHex(match, rng, helperName)
	})

	line = blindDecimalsInLine(line, rng, helperName)
	return line
}

func blindDecimalsInLine(line string, rng *rand.Rand, helperName string) string {
	var buf strings.Builder
	i := 0
	for i < len(line) {
		if unicode.IsDigit(rune(line[i])) {
			start := i
			for i < len(line) && unicode.IsDigit(rune(line[i])) {
				i++
			}
			numStr := line[start:i]

			if start > 0 && (unicode.IsLetter(rune(line[start-1])) || line[start-1] == '_') {
				buf.WriteString(numStr)
				continue
			}
			if i < len(line) && (unicode.IsLetter(rune(line[i])) || line[i] == '_' || line[i] == 'x' || line[i] == 'X') {
				buf.WriteString(numStr)
				continue
			}

			replaced := cbBlindDecimal(numStr, rng, helperName)
			buf.WriteString(replaced)
		} else {
			buf.WriteByte(line[i])
			i++
		}
	}
	return buf.String()
}

func cbBlindHex(match string, rng *rand.Rand, helperName string) string {
	val, err := strconv.ParseUint(match, 0, 64)
	if err != nil {
		return match
	}
	if val == 0 || val == 1 {
		return match
	}
	if val > 0x7FFFFFFFFFFFFFFF {
		return match
	}

	key := rng.Uint64() | 1
	blinded := key ^ val
	if key > 0x7FFFFFFFFFFFFFFF || blinded > 0x7FFFFFFFFFFFFFFF {
		return match
	}
	return fmt.Sprintf("%s(0x%X, 0x%X)", helperName, key, blinded)
}

func cbBlindDecimal(match string, rng *rand.Rand, helperName string) string {
	val, err := strconv.ParseUint(match, 10, 64)
	if err != nil {
		return match
	}
	if val < 10 {
		return match
	}
	if val > 0x7FFFFFFFFFFFFFFF {
		return match
	}

	key := rng.Uint64() | 1
	blinded := key ^ val
	if key > 0x7FFFFFFFFFFFFFFF || blinded > 0x7FFFFFFFFFFFFFFF {
		return match
	}
	return fmt.Sprintf("%s(0x%X, 0x%X)", helperName, key, blinded)
}

func injectBlindHelper(src string, helperName string) string {
	helper := fmt.Sprintf(`
//go:noinline
func %s(a, b int) int { return a ^ b }
`, helperName)

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
		src = src[:insertAt] + helper + src[insertAt:]
	}
	return src
}
