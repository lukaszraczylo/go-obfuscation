// Fake function signature injection.
//
// Injects realistic-looking but dead function definitions into the source
// file. These functions are never called and serve to confuse disassemblers
// by polluting the symbol table with plausible function boundaries, making
// it harder to identify real functions and their purposes.
package transform

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/lukaszraczylo/go-obfuscation/pkg/stringcrypt"
)

type fakeFuncTemplate struct {
	namePattern string
	params      string
	returnType  string
	bodyGen     func(rng *rand.Rand, argName string) string
}

var fakeFuncTemplates = []fakeFuncTemplate{
	{
		namePattern: "_initAuth_obf",
		params:      "token string",
		returnType:  "bool",
		bodyGen: func(rng *rand.Rand, arg string) string {
			v1 := stringcrypt.RandomIdent("_v", 3)
			v2 := stringcrypt.RandomIdent("_v", 3)
			return fmt.Sprintf("\t_ = %s\n\t%s := len(%s)\n\t%s := %s[0] & 0xFF\n\treturn %s > 100 && %s < 0",
				arg, v1, arg, v2, arg, v1, v2)
		},
	},
	{
		namePattern: "_parseConfig_obf",
		params:      "data []byte",
		returnType:  "int",
		bodyGen: func(rng *rand.Rand, arg string) string {
			v1 := stringcrypt.RandomIdent("_c", 3)
			v2 := stringcrypt.RandomIdent("_c", 3)
			return fmt.Sprintf("\t_ = %s\n\t%s := len(%s)\n\t%s := %s * 3\n\t_ = %s\n\treturn %s - %s",
				arg, v1, arg, v2, v1, v2, v1, v2)
		},
	},
	{
		namePattern: "_validateKey_obf",
		params:      "key string, size int",
		returnType:  "bool",
		bodyGen: func(rng *rand.Rand, arg string) string {
			v1 := stringcrypt.RandomIdent("_k", 3)
			v2 := stringcrypt.RandomIdent("_k", 3)
			return fmt.Sprintf("\t%s := len(key)\n\t%s := size ^ 0xDEAD\n\t_ = %s\n\treturn %s == %s && %s != %s",
				v1, v2, v2, v1, v2, v1, v2)
		},
	},
	{
		namePattern: "_hashData_obf",
		params:      "input []byte",
		returnType:  "[32]byte",
		bodyGen: func(rng *rand.Rand, arg string) string {
			v1 := stringcrypt.RandomIdent("_h", 3)
			return fmt.Sprintf("\tvar %s [32]byte\n\t_ = %s\n\tfor _i := range %s {\n\t\t%s[_i] = byte(_i)\n\t}\n\treturn %s",
				v1, arg, arg, v1, v1)
		},
	},
	{
		namePattern: "_encodePayload_obf",
		params:      "buf []byte, offset int",
		returnType:  "int",
		bodyGen: func(rng *rand.Rand, arg string) string {
			v1 := stringcrypt.RandomIdent("_e", 3)
			return fmt.Sprintf("\t_ = buf\n\t_ = offset\n\t%s := len(buf) + offset\n\treturn %s ^ %s",
				v1, v1, v1)
		},
	},
	{
		namePattern: "_checkPerms_obf",
		params:      "uid int, gid int",
		returnType:  "bool",
		bodyGen: func(rng *rand.Rand, arg string) string {
			v1 := stringcrypt.RandomIdent("_p", 3)
			return fmt.Sprintf("\t%s := uid ^ gid\n\treturn %s > 0 && %s < 0 && uid == gid && uid != gid",
				v1, v1, v1)
		},
	},
	{
		namePattern: "_readStream_obf",
		params:      "path string",
		returnType:  "[]byte",
		bodyGen: func(rng *rand.Rand, arg string) string {
			v1 := stringcrypt.RandomIdent("_r", 3)
			v2 := stringcrypt.RandomIdent("_r", 3)
			return fmt.Sprintf("\t_ = %s\n\t%s := len(%s)\n\t%s := make([]byte, %s)\n\tfor _i := range %s {\n\t\t%s[_i] = 0\n\t}\n\treturn %s",
				arg, v1, arg, v2, v1, v2, v2, v2)
		},
	},
	{
		namePattern: "_formatLog_obf",
		params:      "level int, msg string",
		returnType:  "string",
		bodyGen: func(rng *rand.Rand, arg string) string {
			v1 := stringcrypt.RandomIdent("_l", 3)
			return fmt.Sprintf("\t_ = level\n\t%s := len(msg)\n\tif %s > 1000000 {\n\t\treturn \"\"\n\t}\n\treturn msg[:%s]",
				v1, v1, v1)
		},
	},
}

// InjectFakeSignatures inserts 2-5 fake function definitions per file
// that look realistic but are never called.
func InjectFakeSignatures(src string) string {
	rng := rand.New(rand.NewSource(rand.Int63()))

	numFake := rng.Intn(4) + 2 // 2-5 fake functions
	var fakeFuncs strings.Builder

	// Select random templates without replacement
	perm := rng.Perm(len(fakeFuncTemplates))
	for i := 0; i < numFake && i < len(fakeFuncTemplates); i++ {
		tmpl := fakeFuncTemplates[perm[i]]
		suffix := fmt.Sprintf("%04X", rng.Intn(0xFFFF))
		funcName := tmpl.namePattern + suffix

		argName := extractFirstArgName(tmpl.params)

		fakeFuncs.WriteString("\n//go:noinline\n")
		fakeFuncs.WriteString(fmt.Sprintf("func %s(%s) %s {\n", funcName, tmpl.params, tmpl.returnType))
		fakeFuncs.WriteString(tmpl.bodyGen(rng, argName))
		fakeFuncs.WriteString("\n}\n")
	}

	// Inject at package level, after imports
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
		src = src[:insertAt] + fakeFuncs.String() + src[insertAt:]
	}

	return src
}

func extractFirstArgName(params string) string {
	params = strings.TrimSpace(params)
	if params == "" {
		return "_"
	}
	parts := strings.SplitN(params, ",", 2)
	first := strings.TrimSpace(parts[0])
	fields := strings.Fields(first)
	if len(fields) >= 1 {
		return fields[0]
	}
	return "_"
}

// InjectMoreFakeSignatures generates additional fake functions with
// random realistic names and bodies for deeper obfuscation.
func InjectMoreFakeSignatures(src string, count int) string {
	rng := rand.New(rand.NewSource(rand.Int63()))

	prefixes := []string{
		"_resolveAddr", "_buildRequest", "_handleResp", "_writeLog",
		"_parseHeader", "_checkAuth", "_compressData", "_decompressBuf",
		"_verifySig", "_loadCache", "_flushBuffer", "_retryConn",
		"_closeSocket", "_allocMem", "_releaseLock", "_acquireLock",
		"_serializeMsg", "_deserializeMsg", "_encodeURL", "_decodeURL",
	}

	paramSets := []struct {
		params     string
		returnType string
	}{
		{"addr string, port int", "error"},
		{"data []byte", "int"},
		{"key string", "bool"},
		{"src, dst string", "string"},
		{"n int", "int64"},
		{"buf []byte, offset int", "[]byte"},
		{"flag bool, name string", "string"},
		{"x, y int64", "int64"},
	}

	var fakeFuncs strings.Builder

	for i := 0; i < count; i++ {
		prefix := prefixes[rng.Intn(len(prefixes))]
		suffix := fmt.Sprintf("%04X", rng.Intn(0xFFFF))
		funcName := prefix + "_obf" + suffix

		pset := paramSets[rng.Intn(len(paramSets))]
		argName := extractFirstArgName(pset.params)

		body := generateRandomBody(rng, argName, pset.returnType)

		fakeFuncs.WriteString("\n//go:noinline\n")
		fakeFuncs.WriteString(fmt.Sprintf("func %s(%s) %s {\n", funcName, pset.params, pset.returnType))
		fakeFuncs.WriteString(body)
		fakeFuncs.WriteString("\n}\n")
	}

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
		src = src[:insertAt] + fakeFuncs.String() + src[insertAt:]
	}

	return src
}

// generateRandomBody creates a plausible-looking function body that computes
// something meaningless but looks legitimate.
func generateRandomBody(rng *rand.Rand, argName, returnType string) string {
	var sb strings.Builder
	numStmts := rng.Intn(6) + 3 // 3-8 statements

	vars := make([]string, numStmts)
	for i := range vars {
		vars[i] = stringcrypt.RandomIdent("_x", 3)
	}

	// Always start with consuming the argument
	sb.WriteString(fmt.Sprintf("\t_ = %s\n", argName))

	for i := 0; i < numStmts; i++ {
		switch rng.Intn(5) {
		case 0:
			// Assignment from arithmetic
			val := rng.Intn(0xFFFF) + 1
			sb.WriteString(fmt.Sprintf("\t%s := %d ^ 0x%X\n", vars[i], val, rng.Intn(0xFFFF)))
		case 1:
			// Boolean expression
			sb.WriteString(fmt.Sprintf("\t%s := %d > %d && %d < %d\n",
				vars[i], rng.Intn(100), rng.Intn(100)+200, rng.Intn(100), rng.Intn(100)+200))
		case 2:
			// Self-referencing computation
			if i > 0 {
				sb.WriteString(fmt.Sprintf("\t%s = %s + %d\n", vars[i-1], vars[i-1], rng.Intn(1000)))
			} else {
				sb.WriteString(fmt.Sprintf("\t%s := %d\n", vars[i], rng.Intn(0xFFFF)))
			}
		case 3:
			// Dead code branch
			sb.WriteString(fmt.Sprintf("\tif false { %s = %s }\n", vars[i], vars[max(0, i-1)]))
		case 4:
			// Bitwise operation
			sb.WriteString(fmt.Sprintf("\t%s := int64(%d) << %d\n", vars[i], rng.Intn(256), rng.Intn(8)))
		}
	}

	// Return something based on the return type
	switch returnType {
	case "bool":
		sb.WriteString(fmt.Sprintf("\treturn %s && !%s\n", vars[0], vars[0]))
	case "int", "int64":
		sb.WriteString(fmt.Sprintf("\treturn %s - %s\n", vars[0], vars[0]))
	case "string":
		sb.WriteString("\treturn \"\"\n")
	case "[]byte":
		sb.WriteString("\treturn nil\n")
	case "[32]byte":
		sb.WriteString(fmt.Sprintf("\tvar %s [32]byte\n\treturn %s\n", vars[numStmts-1], vars[numStmts-1]))
	case "error":
		sb.WriteString("\treturn nil\n")
	default:
		sb.WriteString(fmt.Sprintf("\treturn %s\n", vars[0]))
	}

	return sb.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
