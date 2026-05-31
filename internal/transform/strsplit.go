// Long string splitting transformation.
//
// Splits string literals longer than a threshold into concatenated chunks
// of randomized length (5-9 characters). This ensures that even if string
// encryption is bypassed, long sensitive values like GPG keys, API keys,
// and connection strings cannot be found via `strings` on the binary.
package transform

import (
	"fmt"
	"math/rand"
	"strings"
)

const (
	splitMinChunk = 5
	splitMaxChunk = 9
	splitMinLen   = 20
)

// SplitLongStrings breaks string literals longer than splitMinLen into
// concatenated chunks of 5-9 characters each.
func SplitLongStrings(src string) string {
	rng := rand.New(rand.NewSource(rand.Int63()))
	return splitStringLiterals(src, rng)
}

func splitStringLiterals(src string, rng *rand.Rand) string {
	var buf strings.Builder
	buf.Grow(len(src) * 2)

	i := 0
	inImport := false
	parenImport := false

	for i < len(src) {
		// Track import block context
		rest := src[i:]
		if !inImport && strings.HasPrefix(rest, "import") {
			afterImport := strings.TrimSpace(rest[6:])
			if strings.HasPrefix(afterImport, "(") {
				inImport = true
				parenImport = true
			} else if strings.HasPrefix(afterImport, "\"") {
				inImport = true
				parenImport = false
			}
		}

		if inImport {
			if parenImport && src[i] == ')' {
				inImport = false
				parenImport = false
			} else if !parenImport && src[i] == '\n' {
				inImport = false
			}
			buf.WriteByte(src[i])
			i++
			continue
		}

		if src[i] == '"' {
			end := findStringEnd(src, i)
			if end == -1 {
				buf.WriteByte(src[i])
				i++
				continue
			}

			literal := src[i : end+1]
			inner := literal[1 : len(literal)-1]

			if len(inner) >= splitMinLen && !containsEscapes(inner) {
				split := splitString(inner, rng)
				buf.WriteString(split)
			} else {
				buf.WriteString(literal)
			}
			i = end + 1
		} else if src[i] == '`' {
			end := findBacktickEnd(src, i)
			if end == -1 {
				buf.WriteByte(src[i])
				i++
				continue
			}

			literal := src[i : end+1]
			inner := literal[1 : len(literal)-1]

			if len(inner) >= splitMinLen {
				split := splitRawString(inner, rng)
				buf.WriteString(split)
			} else {
				buf.WriteString(literal)
			}
			i = end + 1
		} else {
			buf.WriteByte(src[i])
			i++
		}
	}

	return buf.String()
}

func findStringEnd(src string, start int) int {
	i := start + 1
	for i < len(src) {
		if src[i] == '\\' {
			i += 2
			continue
		}
		if src[i] == '"' {
			return i
		}
		i++
	}
	return -1
}

func findBacktickEnd(src string, start int) int {
	for i := start + 1; i < len(src); i++ {
		if src[i] == '`' {
			return i
		}
	}
	return -1
}

func containsEscapes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			return true
		}
	}
	return false
}

func splitString(s string, rng *rand.Rand) string {
	chunks := splitIntoChunks(s, rng)
	if len(chunks) <= 1 {
		return `"` + s + `"`
	}

	var parts []string
	for _, c := range chunks {
		parts = append(parts, `"`+escapeString(c)+`"`)
	}
	return "(" + strings.Join(parts, " + ") + ")"
}

func splitRawString(s string, rng *rand.Rand) string {
	chunks := splitIntoChunks(s, rng)
	if len(chunks) <= 1 {
		return "`" + s + "`"
	}

	var parts []string
	for _, c := range chunks {
		parts = append(parts, `"`+escapeString(c)+`"`)
	}
	return "(" + strings.Join(parts, " + ") + ")"
}

func splitIntoChunks(s string, rng *rand.Rand) []string {
	runes := []rune(s)
	if len(runes) < splitMinLen {
		return []string{s}
	}

	var chunks []string
	pos := 0
	for pos < len(runes) {
		remaining := len(runes) - pos
		if remaining <= splitMaxChunk {
			chunks = append(chunks, string(runes[pos:]))
			break
		}

		chunkLen := splitMinChunk + rng.Intn(splitMaxChunk-splitMinChunk+1)

		if remaining-chunkLen < splitMinChunk && remaining-chunkLen > 0 {
			chunkLen = remaining / 2
			if chunkLen < splitMinChunk {
				chunkLen = splitMinChunk
			}
		}

		chunks = append(chunks, string(runes[pos:pos+chunkLen]))
		pos += chunkLen
	}

	return chunks
}

func escapeString(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\', '"':
			buf.WriteRune('\\')
			buf.WriteRune(r)
		case '\n':
			buf.WriteString(`\n`)
		case '\t':
			buf.WriteString(`\t`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 32 {
				buf.WriteString(fmt.Sprintf(`\x%02x`, r))
			} else {
				buf.WriteRune(r)
			}
		}
	}
	return buf.String()
}
