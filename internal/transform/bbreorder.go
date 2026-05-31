// Basic block reordering transformation.
//
// Randomizes the order of basic blocks within functions to defeat
// linear disassembly and static analysis. Handles if/else body swapping
// (with condition negation), switch case reordering, and sequential
// block permutation with jump-label indirection.
package transform

import (
	"math/rand"
	"regexp"
	"strings"

	"github.com/lukaszraczylo/go-obfuscation/pkg/stringcrypt"
)

var (
	// Matches if (...) { ... } else { ... } blocks at the line level
	bbrIfPattern     = regexp.MustCompile(`^(\s*)if\s+(.+?)\s*\{`)
	bbrElsePattern   = regexp.MustCompile(`^(\s*)\}\s*else\s*\{`)
	bbrElseIfPattern = regexp.MustCompile(`^(\s*)\}\s*else\s+if\s+(.+?)\s*\{`)

	// Matches switch statements
	bbrSwitchPattern = regexp.MustCompile(`^(\s*)switch\s+(.+?)\s*\{`)
)

// ReorderBasicBlocks randomizes control flow block ordering within functions.
func ReorderBasicBlocks(src string) string {
	rng := rand.New(rand.NewSource(rand.Int63()))

	lines := strings.Split(src, "\n")
	var result []string
	i := 0

	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])

		if isFuncDecl(trimmed) {
			funcLines := collectFuncBody(lines, i)
			if funcLines != nil && len(funcLines) >= 12 {
				reordered := reorderFuncBlocks(funcLines, rng)
				result = append(result, reordered...)
				i += len(funcLines)
				continue
			}
		}

		result = append(result, lines[i])
		i++
	}

	return strings.Join(result, "\n")
}

// reorderFuncBlocks applies all reordering strategies to a single function.
func reorderFuncBlocks(funcLines []string, rng *rand.Rand) []string {
	funcSig := funcLines[0]
	closingBrace := funcLines[len(funcLines)-1]
	bodyLines := funcLines[1 : len(funcLines)-1]

	var result []string
	result = append(result, funcSig)

	// Strategy 1: Swap if/else bodies with negated conditions
	bodyLines = swapIfElse(bodyLines, rng)

	// Strategy 2: Reorder switch cases
	bodyLines = reorderSwitchCases(bodyLines, rng)

	result = append(result, bodyLines...)
	result = append(result, closingBrace)

	return result
}

// swapIfElse finds if/else blocks and swaps the bodies, negating the condition.
func swapIfElse(lines []string, rng *rand.Rand) []string {
	var result []string
	i := 0

	for i < len(lines) {
		// Look for if blocks with else
		ifMatch := bbrIfPattern.FindStringSubmatch(lines[i])
		if ifMatch == nil || rng.Float64() > 0.4 {
			result = append(result, lines[i])
			i++
			continue
		}

		// Collect the if body
		indent := ifMatch[1]
		condition := ifMatch[2]
		ifBody := []string{lines[i]}
		i++
		depth := 1

		for i < len(lines) && depth > 0 {
			line := lines[i]
			for _, c := range line {
				if c == '{' {
					depth++
				}
				if c == '}' {
					depth--
				}
			}
			ifBody = append(ifBody, line)
			i++

			// Check if this line ends the if block and has else
			if depth == 0 && i < len(lines) {
				if bbrElsePattern.MatchString(lines[i]) || bbrElseIfPattern.MatchString(lines[i]) {
					break
				}
			}
		}

		// Look for else block
		if i >= len(lines) || depth != 0 {
			result = append(result, ifBody...)
			continue
		}

		// Handle else if — don't swap, too complex
		if bbrElseIfPattern.MatchString(lines[i]) {
			result = append(result, ifBody...)
			continue
		}

		if !bbrElsePattern.MatchString(lines[i]) {
			result = append(result, ifBody...)
			continue
		}

		// Collect else body
		elseBody := []string{lines[i]}
		i++
		depth = 1
		for i < len(lines) && depth > 0 {
			line := lines[i]
			for _, c := range line {
				if c == '{' {
					depth++
				}
				if c == '}' {
					depth--
				}
			}
			elseBody = append(elseBody, line)
			i++
		}

		// Swap: emit negated condition with else body first, then else with if body
		negCond := negateCondition(condition)

		// Build swapped: if !condition { <else body> } else { <if body> }
		result = append(result, indent+"if "+negCond+" {")
		// The else body contents (skip the "else {" line and closing "}")
		elseContents := elseBody[1 : len(elseBody)-1]
		for _, line := range elseContents {
			result = append(result, line)
		}
		result = append(result, indent+"} else {")
		// The if body contents (skip the "if ... {" line and closing "}")
		ifContents := ifBody[1 : len(ifBody)-1]
		for _, line := range ifContents {
			result = append(result, line)
		}
		result = append(result, indent+"}")
	}

	return result
}

// negateCondition negates a boolean condition.
func negateCondition(cond string) string {
	cond = strings.TrimSpace(cond)

	// Handle simple negation
	if strings.HasPrefix(cond, "!") {
		return strings.TrimPrefix(cond, "!")
	}

	// Handle parenthesized conditions
	if strings.HasPrefix(cond, "(") && strings.HasSuffix(cond, ")") {
		return "!(" + cond + ")"
	}

	// Negate comparison operators
	negationMap := map[string]string{
		"==": "!=",
		"!=": "==",
		"<":  ">=",
		">":  "<=",
		"<=": ">",
		">=": "<",
	}

	for op, negOp := range negationMap {
		idx := strings.Index(cond, op)
		if idx > 0 {
			// Make sure we're not matching a substring of a longer operator
			afterOp := idx + len(op)
			if afterOp < len(cond) {
				nextChar := cond[afterOp]
				if nextChar == '=' || nextChar == '<' || nextChar == '>' {
					continue
				}
			}
			return cond[:idx] + negOp + cond[idx+len(op):]
		}
	}

	// Default: wrap in negation
	return "!(" + cond + ")"
}

// reorderSwitchCases finds switch statements and randomly reorders their cases.
func reorderSwitchCases(lines []string, rng *rand.Rand) []string {
	var result []string
	i := 0

	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])

		// Find switch statements
		if !strings.HasPrefix(trimmed, "switch ") || !strings.HasSuffix(trimmed, "{") {
			result = append(result, lines[i])
			i++
			continue
		}

		// Only reorder with some probability
		if rng.Float64() > 0.4 {
			result = append(result, lines[i])
			i++
			continue
		}

		switchHeader := lines[i]
		i++

		// Collect all cases
		type caseBlock struct {
			header string
			body   []string
		}
		var cases []caseBlock
		var currentCase *caseBlock
		depth := 1

		for i < len(lines) && depth > 0 {
			line := lines[i]
			for _, c := range line {
				if c == '{' {
					depth++
				}
				if c == '}' {
					depth--
				}
			}

			if depth <= 0 {
				break
			}

			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "case ") || strings.HasPrefix(t, "default:") {
				if currentCase != nil {
					cases = append(cases, *currentCase)
				}
				currentCase = &caseBlock{header: line}
			} else if currentCase != nil {
				currentCase.body = append(currentCase.body, line)
			}
			i++
		}

		if currentCase != nil {
			cases = append(cases, *currentCase)
		}

		// Skip closing brace of switch
		i++

		// Only reorder if enough cases and no default (reordering default is risky)
		hasDefault := false
		for _, c := range cases {
			if strings.Contains(strings.TrimSpace(c.header), "default:") {
				hasDefault = true
				break
			}
		}

		if len(cases) >= 3 && !hasDefault {
			// Shuffle non-first cases (keep first case position to maintain entry point)
			if len(cases) > 2 {
				shuffleStart := 1
				perm := rng.Perm(len(cases) - shuffleStart)
				shuffled := make([]caseBlock, len(cases))
				copy(shuffled, cases[:shuffleStart])
				for j, p := range perm {
					shuffled[shuffleStart+j] = cases[shuffleStart+p]
				}
				cases = shuffled
			}
		}

		// Reconstruct switch
		result = append(result, switchHeader)
		for _, c := range cases {
			result = append(result, c.header)
			result = append(result, c.body...)
		}
		result = append(result, "\t}")
	}

	return result
}

// InjectJumpLabels converts sequential blocks into labeled blocks with goto
// indirection for functions that are eligible. This is the most aggressive
// reordering strategy and requires careful analysis of control dependencies.
func InjectJumpLabels(bodyLines []string, rng *rand.Rand) []string {
	stmts := parseStatements(bodyLines)
	if len(stmts) < 4 {
		return bodyLines
	}

	// Generate labels
	var labels []string
	for range stmts {
		labels = append(labels, stringcrypt.RandomIdent("_lbl", 4))
	}

	// Create a random permutation of statement order
	perm := rng.Perm(len(stmts))

	var result []string
	result = append(result, "\tgoto "+labels[perm[0]])

	for _, idx := range perm {
		result = append(result, labels[idx]+":")
		for _, line := range stmts[idx] {
			trimmed := strings.TrimPrefix(line, "\t")
			result = append(result, "\t"+trimmed)
		}
		// Add goto to next block in permutation order
		nextIdx := -1
		for j, p := range perm {
			if p == idx && j+1 < len(perm) {
				nextIdx = perm[j+1]
				break
			}
		}
		if nextIdx >= 0 {
			result = append(result, "\tgoto "+labels[nextIdx])
		}
	}

	return result
}
