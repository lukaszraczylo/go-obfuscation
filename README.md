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
│  (cmd/transformer)              │  14 obfuscation passes
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
Size:            2707026     3098114
Symbols:         2864        58
Strings:         15287       4378
Secret leaks:    1 (LIC-*)   0
Function names:  visible     0 (good)
```

## Architecture

```
go-obfuscation/
├── cmd/
│   ├── transformer/       CLI for source transformation
│   ├── demoapp/           Target application with embedded secrets
│   └── inthash/           Integrity hash computation tool
├── internal/
│   └── transform/         Core transformation engine (14 passes)
├── pkg/
│   ├── strenc/            AES-256-GCM encrypted string pool
│   ├── stringcrypt/       XOR string encryption + random identifiers
│   ├── vm/                Stack-based bytecode virtual machine
│   ├── syscallobf/        Obfuscated syscall dispatch
│   ├── integrity/         Binary .text section integrity verification
│   ├── antidebug/         Anti-debugging / anti-hooking checks
│   ├── antidbi/           Frida/DynamoRIO/Pin detection
│   ├── antivm/            VMware/VirtualBox/QEMU detection
│   ├── antiemul/          Emulator detection (timing, CPU, memory)
│   ├── antisandbox/       Sandbox detection (network, environment)
│   ├── pclntab/           gopclntab section corruption
│   ├── typewipe/          Go type metadata destruction
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

### 13. MBA (Mixed Boolean-Arithmetic) Expressions

Replaces simple arithmetic and bitwise operations with equivalent complex expressions.

```go
// Before:
x = a + b

// After:
x = ((a ^ b) + 2 * (a & b))

// Other identities:
// a - b  →  (a ^ b) - 2 * ((^a) & b)
// a ^ b  →  (a | b) - (a & b)
// a & b  →  (a | b) - (a ^ b)
// a | b  →  (a ^ b) + (a & b)
// ^a     →  (-a) - 1
```

Each identity is randomly selected per occurrence. Requires symbolic execution or MBA-Blast-level simplification to reduce.

### 14. Constant Blinding

Replaces integer constants with runtime XOR decryption so no literal values appear in the binary.

```go
// Before:
x = 42

// After:
x = _blind(0xDEADBEEF12345678, 0xDEADBEEF1234565A)  // key ^ (key ^ 42)

//go:noinline
func _blind(a, b uint64) uint64 { return a ^ b }
```

Each constant gets a unique random key. Skips 0, 1, 2 and single-digit values.

### 15. Long String Splitting

Splits string literals ≥20 characters into randomized 5-9 character chunks joined at runtime.

```go
// Before:
key := "sk-proj-FAKE-KEY-1234567890abcdef"

// After:
key := ("sk-pr" + "oj-FA" + "KE-KE" + "Y-123" + "45678" + "90abc" + "def")
```

Ensures `strings` on the binary cannot find contiguous sensitive values like API keys, GPG keys, or connection strings. Skips import paths and strings with escape sequences.

### 16. Function Splitting

Splits function bodies with 8+ statements into fragments dispatched via a state machine.

### 17. Basic Block Reordering

Swaps if/else branches (negating conditions) and shuffles switch cases randomly.

### 18. Fake Function Signatures

Injects 2-5 realistic-but-dead `//go:noinline` functions per file to confuse disassembler function boundary detection.

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
| `checkHardwareBreakpoints()` | Linux | Reads DR0-DR7 debug registers via ptrace child process |
| `checkHardwareBreakpoints()` | Windows | `GetThreadContext` with `CONTEXT_DEBUG_REGISTERS` flag |
| `checkSignalTrap()` | Linux/Darwin | SIGTRAP self-send; if handler doesn't fire, debugger intercepted it |
| `checkReturnAddresses()` | All | Verifies stack PCs are within binary's code section; flags frida/dynamorio/hook names |
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

### Frida/DBI Detection (`pkg/antidbi`)

Detects Dynamic Binary Instrumentation frameworks (Frida, DynamoRIO, Intel Pin).

| Method | Platform | Description |
|--------|----------|-------------|
| Memory maps | Linux | Scans `/proc/self/maps` for frida-agent, frida-gadget, dynamorio, libpin |
| Unix sockets | Linux | Scans `/proc/net/unix` for frida/linjector entries |
| Frida port | All | TCP connect to 127.0.0.1:27042 (Frida default) |
| Thread names | Linux | Reads `/proc/self/task/*/comm` for gmain, frida |
| Loaded images | Darwin | Checks DYLD_INSERT_LIBRARIES + scans lib dirs for frida dylibs |
| Mach ports | Darwin | Checks for re.frida.server, re.frida.agent Mach ports |
| Environment | All | Checks LD_PRELOAD, DYLD_* vars for frida/dynamorio/pin |

`AntiAttach()` background goroutine polls every 500ms and exits on detection.

### VM Environment Detection (`pkg/antivm`)

Detects virtual machine environments to prevent sandbox analysis.

| Method | Platform | Description |
|--------|----------|-------------|
| DMI/SMBIOS | Linux | Reads `/sys/class/dmi/id/{sys_vendor,product_name}` for VMware/VirtualBox/QEMU/KVM/Xen/Parallels |
| MAC prefixes | All | Checks `00:0c:29` (VMware), `08:00:27` (VirtualBox), `52:54:00` (QEMU), `00:1c:42` (Parallels) |
| CPUID | Linux | Checks `/proc/cpuinfo` for hypervisor flag and QEMU CPU model strings |
| Disk devices | Linux | Reads `/sys/block/*/device/model` for VM disk names |
| PCI vendors | Linux | Checks vendor IDs: `15ad` (VMware), `80ee` (VirtualBox), `1234` (QEMU) |
| Timing | All | 100k tight loop; >10ms indicates VM exit overhead |
| Registry | Windows | Checks `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` |
| IOKit | Darwin | Checks `system_profiler` and `ioreg` output for VM devices |

### Anti-Emulation Detection (`pkg/antiemul`)

Detects emulated environments via timing and system characteristics.

- **Timing:** 1M iterations must complete in <500ms (emulators are 10-100x slower)
- **Memory:** System RAM <2GB is suspicious
- **Uptime:** System uptime <60s suggests freshly booted sandbox
- **Core count:** <2 CPU cores is suspicious
- **CPU model:** Checks `/proc/cpuinfo` for QEMU/Virtual/KVM strings (Linux)

### Sandbox Detection (`pkg/antisandbox`)

Detects sandbox-like network and environment characteristics.

- **Interface count:** ≤1 network interface is suspicious
- **MAC prefixes:** VM-specific MAC address prefixes
- **Hostname:** Checks for sandbox/cuckoo/malware/analysis in hostname
- **ARP table:** Empty `/proc/net/arp` is suspicious (Linux)

### gopclntab Corruption (`pkg/pclntab`)

Corrupts the `.gopclntab` section — the #1 tool for Go binary reverse engineering. Breaks IDA/Ghidra Go plugins, GoReSym, and `go tool objdump`.

**Post-compilation (`CorruptPclntab`):**
- Parses ELF/Mach-O/PE to find `.gopclntab` section
- XOR-encrypts function name strings with a random key
- Optionally scrambles magic header bytes and injects fake entries

**Runtime (`RuntimeCorrupt`):**
- Reads `/proc/self/exe` (Linux) or binary path (macOS)
- Parses ELF/Mach-O headers in memory to locate pclntab
- Uses `mprotect` to make section writable, XOR-encrypts names in-place
- Handles all 3 Go pclntab magic variants (Go 1.2+, 1.16+, 1.18+)

### Type Information Stripping (`pkg/typewipe`)

Destroys Go type metadata that tools like Ghidra's Go type recovery depend on.

- **`.typelink`** section: Zeroed out (type linkage info)
- **`.itablink`** section: XOR-encrypted (interface method tables)
- **pclntab names:** Type name strings encrypted via mprotect + XOR

**Warning:** Degrades reflection and panic output. Call during `init()` after the runtime has used type info for setup.

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
go test ./...

# Run all tests fresh (no cache)
go test -count=1 ./...

# CI gate: vet + test in one step
make verify
```

### Test Coverage

| Package | Tests | Focus |
|---|---|---|
| `internal/transform` | 28 | MBA, constant blinding, fake signatures, function splitting, basic-block reorder, opaque predicates, junk strings, splice, dead code |
| `pkg/strenc` | 7 | Per-binary key derivation, XOR stream, seed determinism |
| `pkg/stringcrypt` | 7 | CFB mode round-trip, padding, tamper detection |
| `pkg/pageman` | 14 | Page alignment, mprotect guards, size math, write-after-guard |
| `pkg/integrity` | 14 | SHA-256 of binary, hash hex round-trip, `ClearExpectedHash` for runtime toggling |
| `pkg/pclntab` | 12 | `readUint` bounds (incl. negative offset), parser validation, scramble, corrupt, encrypt |
| `pkg/antisandbox` | 6 | Hostname/MAC lists, `Check`/`CheckNetwork` delegation, no-panic on non-Linux |
| `pkg/antiemul` | 6 | `Check`/`checkCoreCount`/`checkMemory`/`checkUptime`/`checkTiming` no-panic; 1M-iter timing guard |
| `pkg/vm` | 21 | Arithmetic, bitwise, comparisons, jumps, callouts, determinism, junk opcodes |
| `pkg/syscallobf` | 3 | Syscall number resolution, table integrity |

Packages without tests: `pkg/antidbi`, `pkg/antidebug`, `pkg/antivm`, `pkg/typewipe`, `cmd/*`. These rely on the platform-specific or runtime-coupled nature of their operations.

### Makefile Targets

```bash
make help        # List all targets with descriptions
make all         # Build obfuscated binary (default)
make obfuscated  # Full pipeline: transform + garble + integrity hash
make normal      # Build unobfuscated binary for comparison
make compare     # Build both and print size/symbol/string comparison
make transformer # Build only the transformer tool
make inthash     # Build only the integrity hash tool
make run         # Build and run obfuscated binary
make run-normal  # Build and run unobfuscated binary
make test        # Run all package tests
make verify      # go vet + go test (CI gate)
make lint        # gofmt + go vet
make fmt         # gofmt -w on all sources (skips build/)
make clean       # Remove build artifacts
```

Note: `make vet` runs `go vet -unsafeptr=false` — the only legitimate `uintptr→pointer` conversion in the project is the darwin antidebug hook in `pkg/antidebug/antidebug_hook_darwin.go`, which reads function prologues for debugger detection.

## Requirements

- Go 1.26.3+ (darwin/arm64 or linux/amd64)
- `garble` (`go install mvdan.cc/garble@latest`)
- No external Go dependencies (stdlib only)

## Limitations

- **Text-based transformation:** The transformer operates on source text, not Go AST. This limits what can be reliably transformed (e.g., type inference for variable hoisting is heuristic).
- **Garble required:** Stage 2 depends on `mvdan.cc/garble` for name mangling, literal encryption, and binary stripping.
- **Simple function virtualization only:** The VM currently handles len-comparisons and arithmetic. Complex control flow is not virtualized.
- **Windows integrity check:** PE `.text` section hashing works but is less battle-tested than ELF/Mach-O paths.
