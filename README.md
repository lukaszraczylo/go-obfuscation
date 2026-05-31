# Go Binary Obfuscation Toolkit

A multi-layer Go binary obfuscation pipeline that combines source-code transformation, compiler-level obfuscation, and runtime protection to make reverse engineering prohibitively expensive.

## Overview

The toolkit operates as a staged pipeline:

```
Source Code
    │
    ▼
┌─────────────────────────────────┐
│  Stage 1: Source Transformer    │  Text-based source rewriting
│  (cmd/transformer)              │  9 obfuscation passes
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  Stage 2: Garble Compilation    │  garble -literals -tiny
│  (mvdan.cc/garble)              │  -trimpath -ldflags="-s -w"
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  Stage 3: Integrity Hash        │  SHA-256 of .text / __text
│  (cmd/inthash)                  │  section for tamper detection
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  Stage 4: Analysis              │  Size, symbols, strings,
│  (Makefile)                     │  secret leakage scan
└─────────────────────────────────┘
```

## Quick Start

```bash
# Prerequisites
go install mvdan.cc/garble@latest

# Build and compare normal vs obfuscated
make compare

# Run the obfuscated binary
make run

# Run just the transformer
make transformer
```

### `make compare` Output

```
                 Normal      Obfuscated
Size:            2707026     3081170
Symbols:         2864        58
Strings:         15335       4264
Secret leaks:    1 (LIC-*)   0
Function names:  visible     0 (good)
```

## Architecture

```
obfuscator/
├── cmd/
│   ├── transformer/       CLI for source transformation
│   ├── demoapp/           Target application with embedded secrets
│   └── inthash/           Integrity hash computation tool
├── internal/
│   └── transform/         Core transformation engine (9 passes)
├── pkg/
│   ├── strenc/            AES-256-GCM encrypted string pool
│   ├── stringcrypt/       XOR string encryption + random identifiers
│   ├── vm/                Stack-based bytecode virtual machine
│   ├── syscallobf/        Obfuscated syscall dispatch
│   ├── integrity/         Binary .text section integrity verification
│   ├── antidebug/         Anti-debugging / anti-hooking checks
│   └── pageman/           Encrypted memory buffer management
└── Makefile               Full build pipeline
```

## Obfuscation Layers

### 1. String Encryption (`pkg/strenc`)

All string literals are replaced with `_decStr(index)` calls backed by an AES-256-GCM encrypted pool.

**How it works:**
- The transformer scans Go AST for string literals (skipping imports and directives)
- Each plaintext is length-padded to 64-byte blocks with a 2-byte little-endian length prefix
- A random 32-byte master seed is generated per build
- Per-string IVs are generated; subkeys are derived via HMAC-SHA256(masterKey, IV)
- Encryption uses AES-256-GCM with the derived subkey
- The generated code includes `_masterSeed`, `_encEntries`, `_encPool`, and a `//go:noinline` `_decStr()` function
- At runtime, `GetString(index)` decrypts on demand; the plaintext is never present as a static string

**Key derivation (`pkg/strenc/keyderive.go`):**
```
seed ──► HMAC-SHA256(seed, "strenc.masterkey.v1") ──► first 16 bytes
     ──► HMAC-SHA256(seed, "strenc.masterkey.v2") ──► last 16 bytes
     ──► 32-byte master key
```

### 2. Opaque Predicates

Injects always-true conditional branches into function bodies at ~40% probability (after 3+ statements).

**6 always-true expression variants:**
- `(a*7) % 7 == 0`
- `(a ^ a) == 0`
- `^(a | a) == ^a`
- `(a & a) == a`
- `len([N]byte{}) == 0`
- `(b + a) > (b + a - 1)`

These are syntactically valid Go expressions that always evaluate to `true` but require symbolic execution or constant folding to prove.

### 3. Dead Code Injection

Injects always-false conditional branches containing unreachable code at ~30% probability.

**6 always-false expression variants:**
- `(a - a) < 0`
- `func() bool { return 1 < 0 }()`
- `func() bool { var _x = a; return _x > _x }()`
- `func() bool { var _x int = a; _x -= a; return _x > 0 }()`
- `len([N]byte{}) < 0`
- `func() bool { return (a^a) > 0 && (a^a) < 0 }()`

### 4. Bogus Control Flow

Injects computationally expensive but semantically dead branches at ~25% probability.

**4 bogus branch variants:**
- Modulo arithmetic loop: `v := int64(1); for i := 0; i < 10; i++ { v = v*7%49999999 }; return v == 1`
- Squared even check: `v := a*a; return v%2 == 0 && v > 0`
- Byte array length: `v := [4]byte{0x72, 0x6F, 0x6F, 0x74}; return len(v) == 4`
- Summation loop: `v := func() int { n := 0; for i := 1; i <= 100; i++ { n += i }; return n }()`

### 5. Indirect Dispatch

Renames unexported functions and creates thin wrappers to obscure call targets.

```go
// Before:
func generateToken(userID string) string { ... }

// After:
func generateToken_obf4721(userID string) string { ... }  // renamed
func generateToken(userID string) string {                 // wrapper
    return generateToken_obf4721(userID)
}
```

Skips `main`, `init`, exported functions, and `_`-prefixed functions.

### 6. Control-Flow Flattening

Converts function bodies into a state-machine dispatcher pattern.

```go
// Before:                          // After:
func foo() {                       func foo() {
    a := 1                            _stX := 0
    b := a + 2                        for {
    c := b * 3                            switch _stX {
    return c                              case 0: a = 1; _stX = 1
}                                         case 1: b = a + 2; _stX = 2
                                          case 2: c = b * 3; _stX = 3
                                          case 3: return c
                                          default: return
                                      }
                                  }
                              }
```

**Safety checks:**
- Only applies to functions with 5+ body lines
- Excludes `main` and `init` functions
- Pre-scan validates all `:=` assignments have inferrable types before hoisting
- Validates variable names are valid Go identifiers (avoids misinterpreting injected opaque predicates)
- Multi-var declarations (`a, b := ...`) are handled separately

### 7. Code Splicing

Similar to flattening but targets functions with `return` statements, splitting them into 2-3 fragments joined by a state machine.

### 8. Build ID Polymorphism

Injects a unique build identifier derived from the build seed:

```go
var _buildID = "BUILD_1780185895842347000_A3F2B1C9" // polymorphic build marker
var _ = _buildID
```

Every build with a different seed produces a structurally different binary, defeating signature-based detection.

### 9. Function Virtualization (`pkg/vm`)

Replaces simple functions with a custom stack-based bytecode VM.

**Supported patterns:**
- `len(x) > N`, `len(x) == N`, `len(x) < N`, `len(x) >= N`
- Two-param arithmetic: `a+b`, `a-b`, `a*b`, `a/b`, `a%b`, `a^b`, `a&b`, `a|b`
- Single-param arithmetic: `a+N`, `a-N`, `a*N`, etc.

**VM design (`pkg/vm/`):**
- 28 opcodes (0x00-0x1B) + 4 junk opcodes (0x1C-0x1F)
- Stack values XOR-masked with `0x5A5A5A5A5A5A5A5A` to resist memory analysis
- Opcode dispatch key: `0xA5` — all opcodes XOR'd before encoding
- Variable-length instruction encoding (1-9 bytes per instruction)
- External callout mechanism: `PUSH args..., PUSH arity, CALL funcID`
- Unknown opcodes silently consumed (breaks linear disassembly)

**Opcodes:**

| Opcode | Hex  | Arg   | Description |
|--------|------|-------|-------------|
| NOP    | 0x00 | none  | Anti-analysis padding |
| PUSH   | 0x01 | i64   | Push immediate |
| POP    | 0x02 | none  | Discard top |
| DUP    | 0x03 | none  | Duplicate top |
| ADD    | 0x04 | none  | a + b |
| SUB    | 0x05 | none  | a - b |
| MUL    | 0x06 | none  | a * b |
| DIV    | 0x07 | none  | a / b |
| MOD    | 0x08 | none  | a % b |
| XOR    | 0x09 | none  | a ^ b |
| AND    | 0x0A | none  | a & b |
| OR     | 0x0B | none  | a \| b |
| NOT    | 0x0C | none  | ~a |
| SHL    | 0x0D | i8    | a << n |
| SHR    | 0x0E | i8    | a >> n |
| CMP_EQ | 0x0F | none  | a == b ? 1 : 0 |
| CMP_LT | 0x10 | none  | a < b ? 1 : 0 |
| CMP_GT | 0x11 | none  | a > b ? 1 : 0 |
| JMP    | 0x12 | i32   | Unconditional jump |
| JZ     | 0x13 | i32   | Jump if zero |
| JNZ    | 0x14 | i32   | Jump if not zero |
| LOAD   | 0x15 | i16   | Load variable |
| STORE  | 0x16 | i16   | Store variable |
| CALL   | 0x17 | i16   | Call external function |
| RET    | 0x18 | none  | Return |
| HALT   | 0x19 | none  | Stop execution |
| SWAP   | 0x1A | i8    | Swap stack positions |
| ROT    | 0x1B | none  | Rotate top 3 |

**Junk opcodes:** The compiler inserts random junk opcodes (0x1C-0x1F) at ~33% probability between real instructions. The VM silently consumes them via the `default` case, breaking linear disassembly. Use `CompileWith(program, CompileOpts{NoJunk: true})` for deterministic output.

### 10. Anti-Disassembly Injection

Injects junk `[N]byte` variable declarations at ~15% per statement to confuse disassemblers and decompilers.

```go
// Injected junk — valid Go, but semantically dead
var _j1 = [7]byte{0x4e, 0x6f, 0x70, 0x65, 0x21, 0x00, 0x00}
var _j2 = [12]byte{0xde, 0xad, 0xbe, 0xef, ...}
```

These produce opaque byte sequences in the binary that disassemblers cannot reliably skip.

### 11. Junk String Injection

Adds 4-10 fake string constants per file to dilute the `strings` output and increase noise for analysts.

```go
var _js1 = "xK9mP2vL8nQ4wR7yT"
var _js2 = "aB3cD5eF7gH9iJ1kL"
```

These strings have no semantic effect but increase the string table from ~200 to ~4000+ entries, making secret extraction harder.

### 12. Function Pointer Dispatch

Wraps function calls through function pointer variables to obscure call targets.

```go
var _fptr0 = checkLicense_obf4721  // function pointer variable
//go:noinline
func checkLicense(args ...interface{}) interface{} {
    return _fptr0(args...)
}
```

## Runtime Protection Packages

### Syscall Obfuscation (`pkg/syscallobf`)

Hides syscall numbers from static analysis using XOR-encoded dispatch.

- **Encoding:** Each syscall number is XOR'd with a random `uint64` dispatch key generated once via `sync.Once`
- **Linux (`syscall_linux.go`):** Wraps `ptrace` (101), `getpid` (39), `kill` (62), `open` (2), `close` (3), `read` (0), `lseek` (8), `mmap` (9), `mprotect` (10) via `syscall.RawSyscall`
- **Darwin (`syscall_darwin.go`):** Real implementations via encoded SYS_* constants using `syscall.RawSyscall6` — `ptrace`, `sysctl`, `kill`, `getpid`, `mmap`, `mprotect`
- **Windows (`syscall_windows.go`):** `NtQueryInformationProcess`, `NtSetInformationThread` via `ntdll.dll` LazyDLL; `kernel32` ops; `NtProtectVirtualMemory` for mprotect

The anti-debugging package uses these for stealthy `/proc/self/mem` and `/proc/self/maps` access.

### Anti-Debugging (`pkg/antidebug`)

**`Check()` runs all detection methods:**

| Check | Platform | Description |
|-------|----------|-------------|
| `checkPtrace()` | Linux | Reads `/proc/self/status` for non-zero `TracerPid` |
| `checkPtrace()` | Darwin | `sysctl` P_TRACED flag check + `ptrace(PT_DENY_ATTACH)` |
| `disableCoreDump()` | Linux | Writes "0" to `/proc/self/coredump_filter` |
| `checkTiming()` | All | 1M loop iterations must complete in <200ms (detects single-stepping) |
| `checkEnv()` | All | Checks for `GODEBUG`, `DELVE_LISTENER`, `DEBUGINFOD_URL`, `RR_LOG_FILE`, `_JAVA_OPTIONS`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` |
| `checkParentProcess()` | Linux | Reads `/proc/<ppid>/comm`, matches against 12 debugger names |
| `checkFunctionPrologues()` | Linux | Reads `/proc/self/mem` at function addresses, checks for JMP hooks (0xE9, 0xEB, 0xFF 0x25) and INT3 breakpoints (0xCC) |
| `scanForBreakpoints()` | Linux | Parses `/proc/self/maps`, reads executable regions, flags ≥8 consecutive 0xCC bytes |
| Windows anti-debug | Windows | 5 API-based checks + PEB direct read + hardware BP scan + ThreadHideFromDebugger |
| Hook detection | Darwin | Function prologue scanning via reflect pointers, ARM64 B/BR hook detection, INT3 cluster scanning |
| Hook detection | Windows | `ReadProcessMemory` prologue scanning |
| Integrity check | Windows | PE `.text` section SHA-256 hashing via `debug/pe` |

**Background goroutines:**
- `AntiAttach()` — polls `checkPtrace()` every 500ms, exits with code 66 on detection
- `AntiDump()` — re-disables core dumps every 2s

All `/proc` reads use `syscallobf` raw syscalls to avoid `os.Open` hooks.

### Binary Integrity (`pkg/integrity`)

Verifies the binary hasn't been tampered with at runtime.

- **Linux:** SHA-256 of the `.text` ELF section (via `debug/elf`)
- **macOS:** SHA-256 of the `__text` Mach-O section (via `debug/macho`)
- **Fallback:** SHA-256 of the entire file

**Usage:**
```go
// After building, compute hash:
// go run ./cmd/inthash ./mybinary

integrity.SetExpectedHashHex("03b1b8341708322379195b1d4427fb15...")
integrity.StartMonitor(30*time.Second, func(err error) {
    // tamper detected
})
```

`StartMonitor` spawns a goroutine that verifies the hash at the given interval (with random initial jitter). Exits with code 66 on mismatch.

### Encrypted Memory (`pkg/pageman`)

`SecureBuffer` provides XOR-encrypted memory with automatic locking.

**Features:**
- Random 32-byte key per buffer
- XOR encryption with per-byte key rotation (`rotateKey(b, pos) = b<<shift | b>>(8-shift)` where `shift = (pos*3+7)%8`)
- `Access(fn)` — auto-unlock, execute callback with plaintext, auto-relock
- `Close()` — zeros all data and key material
- Thread-safe via `sync.Mutex`

**Guard goroutine (`guard.go`):**
- Watches multiple `SecureBuffer`s
- `enforceAutoLock()` — re-locks buffers that exceeded their `autoLock` duration
- `checkMapsTampering()` — compares `/proc/self/maps` snapshots; force-locks all buffers if the memory map changed (detects debugger attachment / memory mapping modifications)

## Transformer CLI

```
Usage: transformer -src <dir> -dst <dir> [flags]

Flags:
  -src string        Source directory to transform
  -dst string        Destination directory for transformed source
  -strings           Encrypt string literals (default true)
  -opaque            Inject opaque predicates (default true)
  -deadcode          Inject dead code (default true)
  -randomize         Randomize declaration order (default true)
  -indirect          Indirect function dispatch (default true)
  -bogus-cfg         Bogus control-flow injection (default true)
  -flatten           Control-flow flattening (default true)
   -vm                Virtualize simple functions into VM bytecode (default true)
  -buildid           Inject unique build ID constant (default true)
  -anti-disasm       Inject anti-disassembly junk variables (default true)
  -junk-strings      Inject fake strings to dilute strings output (default true)
  -seed int          Build seed for polymorphic output (0 = use current timestamp)
```

## Build Pipeline

The `Makefile` orchestrates the full pipeline:

```makefile
# Stage 1: Source transformation
transformer -src cmd/demoapp -dst build/obfuscated/demoapp -seed=$(SEED)

# Stage 2: Garble compilation
garble -literals -tiny build -buildvcs=false -trimpath \
    -ldflags="-s -w -buildid=" -o build/demoapp-garbled ./build/obfuscated/demoapp

# Stage 3: Integrity hash
go run ./cmd/inthash build/demoapp-garbled

# Stage 4: Analysis
# - Binary size
# - Symbol count (nm)
# - String count (strings)
# - Secret leakage scan
# - Function name visibility
```

## Demo Application

`cmd/demoapp/main.go` contains intentionally leaked secrets for testing:

```go
const (
    apiKey    = "sk-proj-FAKE-KEY-1234567890abcdef"
    secretVal = "super-secret-license-key-DO-NOT-SHARE"
    dbConnStr = "postgres://admin:P@ssw0rd!@db.internal:5432/production"
    jwtSecret = "my-jwt-signing-secret-2024"
)
var licenseKey = "LIC-XXXX-YYYY-ZZZZ-PRODUCTION"
```

The `make compare` target verifies all of these are hidden in the obfuscated binary.

## Testing

```bash
# Run all package tests
go test ./pkg/...

# VM tests (23 tests: arithmetic, bitwise, comparisons, jumps, callouts, determinism, junk opcodes)
go test ./pkg/vm/ -v

# Syscall obfuscation tests
go test ./pkg/syscallobf/ -v

# Vet all source
go vet ./...
```

## Requirements

- Go 1.26.3+ (darwin/arm64 or linux/amd64)
- `garble` (`go install mvdan.cc/garble@latest`)
- No external Go dependencies (stdlib only)

## Limitations

- **Text-based transformation:** The transformer operates on source text, not Go AST. This limits what can be reliably transformed (e.g., type inference for variable hoisting is heuristic).
- **Garble required:** Stage 2 depends on `mvdan.cc/garble` for name mangling, literal encryption, and binary stripping.
- **Simple function virtualization only:** The VM currently handles len-comparisons and arithmetic. Complex control flow is not virtualized.
- **Windows integrity check:** PE `.text` section hashing works but is less battle-tested than ELF/Mach-O paths.
