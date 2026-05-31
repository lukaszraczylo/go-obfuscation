package vm

import (
	"fmt"
)

const (
	maxStackDepth = 1 << 16
	stackMask     = 0x5A5A5A5A5A5A5A5A
)

type VM struct {
	stack    []int64
	sp       int
	vars     map[int]int64
	code     []byte
	pc       int
	halted   bool
	callouts map[int]func([]int64) int64
}

func NewVM(code []byte, callouts map[int]func([]int64) int64) *VM {
	return &VM{
		stack:    make([]int64, maxStackDepth),
		sp:       0,
		vars:     make(map[int]int64),
		code:     code,
		pc:       0,
		halted:   false,
		callouts: callouts,
	}
}

func (vm *VM) push(v int64) {
	if vm.sp >= maxStackDepth {
		panic("vm: stack overflow")
	}
	vm.stack[vm.sp] = v ^ stackMask
	vm.sp++
}

func (vm *VM) pop() int64 {
	if vm.sp <= 0 {
		panic("vm: stack underflow")
	}
	vm.sp--
	return vm.stack[vm.sp] ^ stackMask
}

func (vm *VM) peek() int64 {
	if vm.sp <= 0 {
		panic("vm: stack empty on peek")
	}
	return vm.stack[vm.sp-1] ^ stackMask
}

func (vm *VM) Run() int64 {
	for !vm.halted {
		vm.Step()
	}
	if vm.sp == 0 {
		return 0
	}
	return vm.peek()
}

func (vm *VM) Step() bool {
	if vm.halted || vm.pc >= len(vm.code) {
		vm.halted = true
		return false
	}

	op, arg, size := DecodeInstr(vm.code, vm.pc)
	vm.pc += size

	switch op {
	case OpNop:
		// anti-analysis padding

	case OpPush:
		vm.push(arg)

	case OpPop:
		vm.pop()

	case OpDup:
		v := vm.pop()
		vm.push(v)
		vm.push(v)

	case OpAdd:
		b := vm.pop()
		a := vm.pop()
		vm.push(a + b)

	case OpSub:
		b := vm.pop()
		a := vm.pop()
		vm.push(a - b)

	case OpMul:
		b := vm.pop()
		a := vm.pop()
		vm.push(a * b)

	case OpDiv:
		b := vm.pop()
		a := vm.pop()
		if b == 0 {
			panic("vm: division by zero")
		}
		vm.push(a / b)

	case OpMod:
		b := vm.pop()
		a := vm.pop()
		if b == 0 {
			panic("vm: modulo by zero")
		}
		vm.push(a % b)

	case OpXor:
		b := vm.pop()
		a := vm.pop()
		vm.push(a ^ b)

	case OpAnd:
		b := vm.pop()
		a := vm.pop()
		vm.push(a & b)

	case OpOr:
		b := vm.pop()
		a := vm.pop()
		vm.push(a | b)

	case OpNot:
		a := vm.pop()
		vm.push(^a)

	case OpShl:
		a := vm.pop()
		vm.push(a << uint(arg))

	case OpShr:
		a := vm.pop()
		vm.push(a >> uint(arg))

	case OpCmpEq:
		b := vm.pop()
		a := vm.pop()
		if a == b {
			vm.push(1)
		} else {
			vm.push(0)
		}

	case OpCmpLt:
		b := vm.pop()
		a := vm.pop()
		if a < b {
			vm.push(1)
		} else {
			vm.push(0)
		}

	case OpCmpGt:
		b := vm.pop()
		a := vm.pop()
		if a > b {
			vm.push(1)
		} else {
			vm.push(0)
		}

	case OpJmp:
		vm.pc = int(arg)

	case OpJz:
		v := vm.pop()
		if v == 0 {
			vm.pc = int(arg)
		}

	case OpJnz:
		v := vm.pop()
		if v != 0 {
			vm.pc = int(arg)
		}

	case OpLoad:
		vm.push(vm.vars[int(arg)])

	case OpStore:
		v := vm.pop()
		vm.vars[int(arg)] = v

	case OpCall:
		fnID := int(arg)
		if fn, ok := vm.callouts[fnID]; ok {
			arity := int(vm.pop())
			args := make([]int64, arity)
			for i := arity - 1; i >= 0; i-- {
				args[i] = vm.pop()
			}
			result := fn(args)
			vm.push(result)
		} else {
			panic(fmt.Sprintf("vm: unknown callout ID %d", fnID))
		}

	case OpRet:
		vm.halted = true
		return false

	case OpHalt:
		vm.halted = true
		return false

	case OpSwap:
		n := int(arg)
		if n < 0 || vm.sp-n < 1 || vm.sp < 1 {
			panic("vm: swap out of bounds")
		}
		topIdx := vm.sp - 1
		nthIdx := vm.sp - 1 - n
		vm.stack[topIdx], vm.stack[nthIdx] = vm.stack[nthIdx], vm.stack[topIdx]

	case OpRot:
		if vm.sp < 3 {
			panic("vm: ROT requires 3 elements")
		}
		top := vm.stack[vm.sp-1]
		vm.stack[vm.sp-1] = vm.stack[vm.sp-2]
		vm.stack[vm.sp-2] = vm.stack[vm.sp-3]
		vm.stack[vm.sp-3] = top

	default:
		// Junk opcodes and unknowns are silently consumed
		// This makes disassembly analysis unreliable
	}

	return !vm.halted
}

func (vm *VM) PC() int      { return vm.pc }
func (vm *VM) Halted() bool { return vm.halted }
func (vm *VM) SP() int      { return vm.sp }
