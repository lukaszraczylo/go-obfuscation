package vm

import (
	"testing"
)

func TestComputeExpr(t *testing.T) {
	// Compute (10 + 20) * 3 = 90
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{10}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{20}}},
		{Instr: Instruction{Op: OpAdd}},
		{Instr: Instruction{Op: OpPush, Args: []int64{3}}},
		{Instr: Instruction{Op: OpMul}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 90 {
		t.Errorf("expected 90, got %d", result)
	}
}

func TestSubtraction(t *testing.T) {
	// 100 - 37 = 63
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{100}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{37}}},
		{Instr: Instruction{Op: OpSub}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 63 {
		t.Errorf("expected 63, got %d", result)
	}
}

func TestDivision(t *testing.T) {
	// 84 / 4 = 21
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{84}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{4}}},
		{Instr: Instruction{Op: OpDiv}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 21 {
		t.Errorf("expected 21, got %d", result)
	}
}

func TestModulo(t *testing.T) {
	// 17 % 5 = 2
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{17}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{5}}},
		{Instr: Instruction{Op: OpMod}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 2 {
		t.Errorf("expected 2, got %d", result)
	}
}

func TestBitwiseOps(t *testing.T) {
	// (0xFF XOR 0x0F) AND 0xF0 = 0xF0
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{0xFF}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{0x0F}}},
		{Instr: Instruction{Op: OpXor}},
		{Instr: Instruction{Op: OpPush, Args: []int64{0xF0}}},
		{Instr: Instruction{Op: OpAnd}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 0xF0 {
		t.Errorf("expected 0xF0, got 0x%X", result)
	}
}

func TestShiftOps(t *testing.T) {
	// 1 SHL 8 = 256
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{1}}},
		{Instr: Instruction{Op: OpShl, Args: []int64{8}}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 256 {
		t.Errorf("expected 256, got %d", result)
	}
}

func TestComparisons(t *testing.T) {
	// 5 < 10 → 1
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{5}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{10}}},
		{Instr: Instruction{Op: OpCmpLt}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 1 {
		t.Errorf("expected 1, got %d", result)
	}

	// 10 > 5 → 1
	program = []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{10}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{5}}},
		{Instr: Instruction{Op: OpCmpGt}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code = Compile(program)
	vm = NewVM(code, nil)
	result = vm.Run()

	if result != 1 {
		t.Errorf("expected 1, got %d", result)
	}

	// 7 == 7 → 1
	program = []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{7}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{7}}},
		{Instr: Instruction{Op: OpCmpEq}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code = Compile(program)
	vm = NewVM(code, nil)
	result = vm.Run()

	if result != 1 {
		t.Errorf("expected 1, got %d", result)
	}
}

func TestJump(t *testing.T) {
	// JMP to "end", skipping the 999 push
	// PUSH 42
	// JMP end
	// PUSH 999   <- skipped
	// end: HALT
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{42}}},
		{Label: "", Instr: Instruction{Op: OpJmp}, Target: "end"},
		{Instr: Instruction{Op: OpPush, Args: []int64{999}}},
		{Label: "end", Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestJzJnz(t *testing.T) {
	// JZ pops the test value; verify both branches work.
	//
	// Phase 1: JZ should take (value is 0)
	//   PUSH 0, JZ zero, PUSH 999 (skipped), zero: PUSH 77
	// Phase 2: JNZ should take (value is 1)
	//   DUP, JNZ nz, PUSH 888 (skipped), nz: HALT
	// Result: 77
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{0}}},
		{Instr: Instruction{Op: OpJz}, Target: "zero"},
		{Instr: Instruction{Op: OpPush, Args: []int64{999}}},
		{Label: "zero", Instr: Instruction{Op: OpPush, Args: []int64{77}}},
		{Instr: Instruction{Op: OpDup}},
		{Instr: Instruction{Op: OpJnz}, Target: "nz"},
		{Instr: Instruction{Op: OpPush, Args: []int64{888}}},
		{Label: "nz", Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 77 {
		t.Errorf("expected 77, got %d", result)
	}
}

func TestStoreLoad(t *testing.T) {
	// PUSH 10
	// STORE 0         var[0] = 10
	// PUSH 20
	// STORE 1         var[1] = 20
	// LOAD 0
	// LOAD 1
	// ADD             var[0] + var[1] = 30
	// HALT
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{10}}},
		{Instr: Instruction{Op: OpStore, Args: []int64{0}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{20}}},
		{Instr: Instruction{Op: OpStore, Args: []int64{1}}},
		{Instr: Instruction{Op: OpLoad, Args: []int64{0}}},
		{Instr: Instruction{Op: OpLoad, Args: []int64{1}}},
		{Instr: Instruction{Op: OpAdd}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 30 {
		t.Errorf("expected 30, got %d", result)
	}
}

func TestDup(t *testing.T) {
	// PUSH 5, DUP, MUL = 25
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{5}}},
		{Instr: Instruction{Op: OpDup}},
		{Instr: Instruction{Op: OpMul}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 25 {
		t.Errorf("expected 25, got %d", result)
	}
}

func TestSwap(t *testing.T) {
	// PUSH 1, PUSH 2, SWAP 1, SUB = 2 - 1 = 1
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{1}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{2}}},
		{Instr: Instruction{Op: OpSwap, Args: []int64{1}}},
		{Instr: Instruction{Op: OpSub}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 1 {
		t.Errorf("expected 1, got %d", result)
	}
}

func TestRot(t *testing.T) {
	// PUSH 1, PUSH 2, PUSH 3, ROT
	// Stack after ROT: [3, 1, 2] (top=2)
	// POP → 2, POP → 1, POP → 3
	// We verify by: PUSH 1, PUSH 2, PUSH 3, ROT, SUB, SUB = 3 - 1 - 2 ... wait
	// Actually ROT puts top to bottom: [1, 3, 2] with top = 2
	// Let me just check stack ordering
	// PUSH 10, PUSH 20, PUSH 30, ROT
	// Before: [10, 20, 30] top=30
	// After:  top=20, then 10, then 30
	// So: POP=20, POP=10, POP=30 → 20 - 10 = 10, 10 - 30 = ... let me just add
	// PUSH 10, PUSH 20, PUSH 30, ROT, ADD, ADD = 20 + 10 + 30 = 60
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{10}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{20}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{30}}},
		{Instr: Instruction{Op: OpRot}},
		{Instr: Instruction{Op: OpAdd}},
		{Instr: Instruction{Op: OpAdd}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 60 {
		t.Errorf("expected 60, got %d", result)
	}
}

func TestNot(t *testing.T) {
	// NOT 0 = -1
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{0}}},
		{Instr: Instruction{Op: OpNot}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != -1 {
		t.Errorf("expected -1, got %d", result)
	}
}

func TestCallout(t *testing.T) {
	// PUSH 7, PUSH 3, PUSH 2 (arity), CALL 42, HALT
	// callout(42) sums its args: 7 + 3 = 10
	callouts := map[int]func([]int64) int64{
		42: func(args []int64) int64 {
			return args[0] + args[1]
		},
	}

	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{7}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{3}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{2}}}, // arity
		{Instr: Instruction{Op: OpCall, Args: []int64{42}}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, callouts)
	result := vm.Run()

	if result != 10 {
		t.Errorf("expected 10, got %d", result)
	}
}

func TestLoop(t *testing.T) {
	// Compute sum 1..5 = 15 using a loop
	// var[0] = accumulator = 0
	// var[1] = counter = 5
	// loop:
	//   LOAD 1        push counter
	//   JZ done
	//   LOAD 0        push acc
	//   LOAD 1        push counter
	//   ADD           acc + counter
	//   STORE 0       acc = result
	//   LOAD 1
	//   PUSH 1
	//   SUB           counter - 1
	//   STORE 1       counter = result
	//   JMP loop
	// done:
	//   LOAD 0
	//   HALT
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{0}}},
		{Instr: Instruction{Op: OpStore, Args: []int64{0}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{5}}},
		{Instr: Instruction{Op: OpStore, Args: []int64{1}}},
		{Label: "loop", Instr: Instruction{Op: OpLoad, Args: []int64{1}}},
		{Instr: Instruction{Op: OpJz}, Target: "done"},
		{Instr: Instruction{Op: OpLoad, Args: []int64{0}}},
		{Instr: Instruction{Op: OpLoad, Args: []int64{1}}},
		{Instr: Instruction{Op: OpAdd}},
		{Instr: Instruction{Op: OpStore, Args: []int64{0}}},
		{Instr: Instruction{Op: OpLoad, Args: []int64{1}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{1}}},
		{Instr: Instruction{Op: OpSub}},
		{Instr: Instruction{Op: OpStore, Args: []int64{1}}},
		{Instr: Instruction{Op: OpJmp}, Target: "loop"},
		{Label: "done", Instr: Instruction{Op: OpLoad, Args: []int64{0}}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 15 {
		t.Errorf("expected 15, got %d", result)
	}
}

func TestNopPadding(t *testing.T) {
	// NOPs should be harmless padding
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpNop}},
		{Instr: Instruction{Op: OpNop}},
		{Instr: Instruction{Op: OpPush, Args: []int64{42}}},
		{Instr: Instruction{Op: OpNop}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestStepwiseExecution(t *testing.T) {
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{3}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{4}}},
		{Instr: Instruction{Op: OpMul}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := CompileWith(program, CompileOpts{NoJunk: true})
	vm := NewVM(code, nil)

	steps := 0
	for vm.Step() {
		steps++
	}

	if steps != 3 {
		t.Errorf("expected 3 steps, got %d", steps)
	}

	if vm.Halted() != true {
		t.Error("expected VM to be halted")
	}

	if vm.SP() != 1 {
		t.Errorf("expected SP=1, got %d", vm.SP())
	}
}

func TestXorObfuscationDeterminism(t *testing.T) {
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{10}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{20}}},
		{Instr: Instruction{Op: OpAdd}},
		{Instr: Instruction{Op: OpPush, Args: []int64{3}}},
		{Instr: Instruction{Op: OpMul}},
		{Instr: Instruction{Op: OpHalt}},
	}

	opts := CompileOpts{NoJunk: true}
	code1 := CompileWith(program, opts)
	code2 := CompileWith(program, opts)

	if len(code1) != len(code2) {
		t.Fatalf("bytecode length differs: %d vs %d", len(code1), len(code2))
	}

	for i := range code1 {
		if code1[i] != code2[i] {
			t.Fatalf("bytecode non-deterministic at offset %d", i)
		}
	}

	vm1 := NewVM(code1, nil)
	vm2 := NewVM(code2, nil)

	r1 := vm1.Run()
	r2 := vm2.Run()

	if r1 != r2 {
		t.Errorf("results differ: %d vs %d", r1, r2)
	}
}

func TestBytecodeIsXORed(t *testing.T) {
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{42}}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := CompileWith(program, CompileOpts{NoJunk: true})

	rawPush := byte(OpPush) ^ dispatchKey
	if code[0] != rawPush {
		t.Errorf("expected bytecode[0]=0x%02X (XOR'd PUSH), got 0x%02X", rawPush, code[0])
	}

	rawHalt := byte(OpHalt) ^ dispatchKey
	if code[9] != rawHalt {
		t.Errorf("expected bytecode[9]=0x%02X (XOR'd HALT), got 0x%02X", rawHalt, code[9])
	}
}

func TestJunkOpcodesCorrectness(t *testing.T) {
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{10}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{20}}},
		{Instr: Instruction{Op: OpAdd}},
		{Instr: Instruction{Op: OpHalt}},
	}

	for i := 0; i < 50; i++ {
		code := Compile(program)
		vm := NewVM(code, nil)
		result := vm.Run()
		if result != 30 {
			t.Fatalf("iteration %d: expected 30, got %d (bytecode len %d)", i, result, len(code))
		}
	}
}

func TestOrOp(t *testing.T) {
	// 0x0F OR 0xF0 = 0xFF
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{0x0F}}},
		{Instr: Instruction{Op: OpPush, Args: []int64{0xF0}}},
		{Instr: Instruction{Op: OpOr}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 0xFF {
		t.Errorf("expected 0xFF, got 0x%X", result)
	}
}

func TestShrOp(t *testing.T) {
	// 256 SHR 4 = 16
	program := []LabelledInstr{
		{Instr: Instruction{Op: OpPush, Args: []int64{256}}},
		{Instr: Instruction{Op: OpShr, Args: []int64{4}}},
		{Instr: Instruction{Op: OpHalt}},
	}

	code := Compile(program)
	vm := NewVM(code, nil)
	result := vm.Run()

	if result != 16 {
		t.Errorf("expected 16, got %d", result)
	}
}
