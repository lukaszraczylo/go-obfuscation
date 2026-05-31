// Function splitting transformation.
//
// Splits function bodies with 8+ statements into fragments called via
// indirect dispatch using a state machine pattern. Shared variables are
// hoisted and passed between fragments. Each fragment is marked go:noinline
// to prevent the compiler from re-inlining the split code.
package transform

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/lukaszraczylo/go-obfuscation/pkg/stringcrypt"
)

// SplitFunctions splits eligible function bodies into fragments called
// through a state-machine dispatcher.
func SplitFunctions(src string) string {
	rng := rand.New(rand.NewSource(rand.Int63()))

	lines := strings.Split(src, "\n")
	var result []string
	i := 0

	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])

		if isFuncDecl(trimmed) && !isMainOrInit(trimmed) {
			funcLines := collectFuncBody(lines, i)
			if funcLines != nil {
				bodyLines := funcLines[1 : len(funcLines)-1]
				funcSig := funcLines[0]
				closingBrace := funcLines[len(funcLines)-1]

				if shouldSplit(bodyLines) && rng.Float64() < 0.5 {
					split := splitFunctionBody(funcSig, bodyLines, closingBrace, rng)
					result = append(result, split...)
					i += len(funcLines)
					continue
				}
			}
		}

		result = append(result, lines[i])
		i++
	}

	return strings.Join(result, "\n")
}

func isFuncDecl(trimmed string) bool {
	return strings.HasPrefix(trimmed, "func ") && strings.HasSuffix(trimmed, "{")
}

func isMainOrInit(trimmed string) bool {
	return strings.Contains(trimmed, "main") || strings.Contains(trimmed, "init()")
}

// collectFuncBody returns the lines of a function (signature through closing brace)
// starting at lineIdx. Returns nil if not a complete function.
func collectFuncBody(lines []string, lineIdx int) []string {
	if lineIdx >= len(lines) {
		return nil
	}

	funcLines := []string{lines[lineIdx]}
	i := lineIdx + 1
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

	if depth != 0 {
		return nil
	}

	return funcLines
}

// shouldSplit determines if a function body is worth splitting.
// Requires 8+ statements and no disqualifying patterns.
func shouldSplit(bodyLines []string) bool {
	stmtCount := 0
	for _, line := range bodyLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "{" || trimmed == "}" {
			continue
		}
		// Skip functions with early returns, goto, or defer
		if strings.HasPrefix(trimmed, "return ") || trimmed == "return" {
			if stmtCount < 3 {
				return false // Early return — don't split
			}
		}
		if strings.HasPrefix(trimmed, "goto ") || strings.HasPrefix(trimmed, "defer ") {
			return false
		}
		// Skip if there are labels
		if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "case ") && !strings.HasPrefix(trimmed, "default") {
			return false
		}
		stmtCount++
	}
	return stmtCount >= 8
}

// splitFunctionBody splits a function body into fragments using a state machine.
func splitFunctionBody(funcSig string, bodyLines []string, closingBrace string, rng *rand.Rand) []string {
	var result []string
	result = append(result, funcSig)

	// Parse statements from body
	stmts := parseStatements(bodyLines)
	if len(stmts) < 4 {
		// Not enough statements; return unmodified
		result = append(result, bodyLines...)
		result = append(result, closingBrace)
		return result
	}

	// Determine number of fragments (2-4)
	numFragments := 2
	if len(stmts) >= 12 {
		numFragments = 3
	}
	if len(stmts) >= 16 {
		numFragments = 4
	}

	// Collect variables declared with := in the body so we can hoist them
	var hoistedVars []string
	declaredVars := map[string]bool{}
	var cleanedStmts [][]string

	for _, stmt := range stmts {
		var cleaned []string
		for _, line := range stmt {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, ":=") {
				parts := strings.SplitN(trimmed, ":=", 2)
				varName := strings.TrimSpace(parts[0])
				rhs := strings.TrimSpace(parts[1])

				names := splitVarNames(varName)
				allValid := true
				for _, n := range names {
					if !isValidIdent(n) {
						allValid = false
						break
					}
				}

				if allValid {
					for _, n := range names {
						if !declaredVars[n] {
							hoistedVars = append(hoistedVars, "\tvar "+n+" "+inferVarType(rhs))
							declaredVars[n] = true
						}
					}
					cleaned = append(cleaned, "\t"+varName+" = "+rhs)
				} else {
					cleaned = append(cleaned, line)
				}
			} else {
				cleaned = append(cleaned, line)
			}
		}
		cleanedStmts = append(cleanedStmts, cleaned)
	}

	// Emit hoisted variables
	for _, v := range hoistedVars {
		result = append(result, v)
	}

	// Build state machine
	stateVar := stringcrypt.RandomIdent("_sf", 4)
	result = append(result, "\t"+stateVar+" := 0")

	// Determine return variable if last statement is a return
	returnVar := ""
	lastStmtLines := cleanedStmts[len(cleanedStmts)-1]
	if len(lastStmtLines) > 0 {
		lastTrimmed := strings.TrimSpace(lastStmtLines[len(lastStmtLines)-1])
		if strings.HasPrefix(lastTrimmed, "return ") {
			returnExpr := strings.TrimPrefix(lastTrimmed, "return ")
			returnVar = stringcrypt.RandomIdent("_ret", 4)
			result = append(result, "\tvar "+returnVar+" "+inferVarType(returnExpr))
			cleanedStmts[len(cleanedStmts)-1][len(lastStmtLines)-1] = "\t" + returnVar + " = " + returnExpr
		}
	}

	result = append(result, "\tfor {")
	result = append(result, "\t\tswitch "+stateVar+" {")

	// Distribute statements across fragments
	fragmentSize := len(cleanedStmts) / numFragments
	for f := 0; f < numFragments; f++ {
		result = append(result, fmt.Sprintf("\t\tcase %d:", f))
		start := f * fragmentSize
		end := (f + 1) * fragmentSize
		if f == numFragments-1 {
			end = len(cleanedStmts)
		}

		for j := start; j < end; j++ {
			for _, line := range cleanedStmts[j] {
				// Re-indent for inside switch case
				trimmed := strings.TrimPrefix(line, "\t")
				result = append(result, "\t\t\t"+trimmed)
			}
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
	}

	result = append(result, "\t\tdefault:")
	if returnVar != "" {
		result = append(result, "\t\t\treturn "+returnVar)
	} else {
		result = append(result, "\t\t\treturn")
	}
	result = append(result, "\t\t}")
	result = append(result, "\t}")
	result = append(result, closingBrace)

	return result
}

// parseStatements splits body lines into statement groups.
// Each group is a complete statement (may span multiple lines for blocks).
func parseStatements(bodyLines []string) [][]string {
	var statements [][]string
	var current []string
	depth := 0

	for _, line := range bodyLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "{" || trimmed == "}" {
			continue
		}

		for _, c := range trimmed {
			if c == '{' {
				depth++
			}
			if c == '}' {
				depth--
			}
		}

		current = append(current, line)

		if depth <= 0 {
			statements = append(statements, current)
			current = nil
			depth = 0
		}
	}

	if len(current) > 0 {
		statements = append(statements, current)
	}

	return statements
}

func splitVarNames(varPart string) []string {
	varPart = strings.TrimSpace(varPart)
	if strings.Contains(varPart, ",") {
		var names []string
		for _, n := range strings.Split(varPart, ",") {
			names = append(names, strings.TrimSpace(n))
		}
		return names
	}
	return []string{varPart}
}

func inferVarType(rhs string) string {
	rhs = strings.TrimSpace(rhs)
	if strings.HasPrefix(rhs, "\"") || strings.HasPrefix(rhs, "`") || strings.HasPrefix(rhs, "fmt.") {
		return "string"
	}
	if strings.HasPrefix(rhs, "[]byte") || strings.HasPrefix(rhs, "make([]byte") {
		return "[]byte"
	}
	if rhs == "true" || rhs == "false" {
		return "bool"
	}
	if strings.HasPrefix(rhs, "[") {
		return "" // array — skip
	}
	// Default to int64 for numeric/unknown types
	return "int64"
}

// InjectSplitFragments generates standalone fragment helper functions for a
// more aggressive splitting strategy where fragments are separate functions
// rather than switch cases. This is an alternative to the state-machine approach.
func InjectSplitFragments(fragments []string, rng *rand.Rand) string {
	var sb strings.Builder
	for i, frag := range fragments {
		fragName := stringcrypt.RandomIdent(fmt.Sprintf("_frag%d_", i), 4)
		sb.WriteString("//go:noinline\n")
		sb.WriteString(fmt.Sprintf("func %s() {\n", fragName))
		sb.WriteString(frag)
		sb.WriteString("\n}\n")
	}
	return sb.String()
}
