package vm

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Instruction struct {
	Op   Opcode
	Args []int64
}

type LabelledInstr struct {
	Label  string
	Instr  Instruction
	Target string
}

type CompileOpts struct {
	NoJunk bool
}

func Compile(program []LabelledInstr) []byte {
	return CompileWith(program, CompileOpts{})
}

func CompileWith(program []LabelledInstr, opts CompileOpts) []byte {
	labelAddrs := make(map[string]int)

	type fixup struct {
		offset int
		op     Opcode
		target string
	}
	var fixups []fixup
	var bytecode []byte

	junkOpcodes := []Opcode{opJunkA, opJunkB, opJunkC, opJunkD}

	for _, entry := range program {
		if entry.Label != "" {
			labelAddrs[entry.Label] = len(bytecode)
		}

		if !opts.NoJunk && shouldInsertJunk() {
			junkOp := junkOpcodes[randIntn(len(junkOpcodes))]
			bytecode = append(bytecode, encodeOp(junkOp))
		}

		instr := entry.Instr
		isJump := instr.Op == OpJmp || instr.Op == OpJz || instr.Op == OpJnz

		if isJump && entry.Target != "" {
			fixups = append(fixups, fixup{
				offset: len(bytecode),
				op:     instr.Op,
				target: entry.Target,
			})
			ph := make([]byte, InstrSize(instr.Op))
			ph[0] = encodeOp(instr.Op)
			bytecode = append(bytecode, ph...)
			continue
		}

		arg := int64(0)
		if len(instr.Args) > 0 {
			arg = instr.Args[0]
		}
		bytecode = append(bytecode, EncodeInstr(instr.Op, arg)...)
	}

	for _, f := range fixups {
		addr, ok := labelAddrs[f.target]
		if !ok {
			panic(fmt.Sprintf("vm: undefined label %q", f.target))
		}
		enc := EncodeInstr(f.op, int64(addr))
		copy(bytecode[f.offset:], enc)
	}

	return bytecode
}

func shouldInsertJunk() bool {
	return randIntn(3) == 0
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	b, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(b.Int64())
}
