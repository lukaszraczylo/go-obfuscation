package vm

import (
	"fmt"
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

func Compile(program []LabelledInstr) []byte {
	labelAddrs := make(map[string]int)

	type fixup struct {
		offset int
		op     Opcode
		target string
	}
	var fixups []fixup
	var bytecode []byte

	for _, entry := range program {
		if entry.Label != "" {
			labelAddrs[entry.Label] = len(bytecode)
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
