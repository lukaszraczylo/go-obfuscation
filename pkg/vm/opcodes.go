package vm

import (
	"encoding/binary"
	"fmt"
)

type Opcode byte

const (
	OpNop   Opcode = 0x00
	OpPush  Opcode = 0x01
	OpPop   Opcode = 0x02
	OpDup   Opcode = 0x03
	OpAdd   Opcode = 0x04
	OpSub   Opcode = 0x05
	OpMul   Opcode = 0x06
	OpDiv   Opcode = 0x07
	OpMod   Opcode = 0x08
	OpXor   Opcode = 0x09
	OpAnd   Opcode = 0x0A
	OpOr    Opcode = 0x0B
	OpNot   Opcode = 0x0C
	OpShl   Opcode = 0x0D
	OpShr   Opcode = 0x0E
	OpCmpEq Opcode = 0x0F
	OpCmpLt Opcode = 0x10
	OpCmpGt Opcode = 0x11
	OpJmp   Opcode = 0x12
	OpJz    Opcode = 0x13
	OpJnz   Opcode = 0x14
	OpLoad  Opcode = 0x15
	OpStore Opcode = 0x16
	OpCall  Opcode = 0x17
	OpRet   Opcode = 0x18
	OpHalt  Opcode = 0x19
	OpSwap  Opcode = 0x1A
	OpRot   Opcode = 0x1B
	opJunkA Opcode = 0x1C
	opJunkB Opcode = 0x1D
	opJunkC Opcode = 0x1E
	opJunkD Opcode = 0x1F
)

const dispatchKey byte = 0xA5

var opcodeNames = map[Opcode]string{
	OpNop: "NOP", OpPush: "PUSH", OpPop: "POP", OpDup: "DUP",
	OpAdd: "ADD", OpSub: "SUB", OpMul: "MUL", OpDiv: "DIV",
	OpMod: "MOD", OpXor: "XOR", OpAnd: "AND", OpOr: "OR",
	OpNot: "NOT", OpShl: "SHL", OpShr: "SHR", OpCmpEq: "CMP_EQ",
	OpCmpLt: "CMP_LT", OpCmpGt: "CMP_GT", OpJmp: "JMP", OpJz: "JZ",
	OpJnz: "JNZ", OpLoad: "LOAD", OpStore: "STORE", OpCall: "CALL",
	OpRet: "RET", OpHalt: "HALT", OpSwap: "SWAP", OpRot: "ROT",
}

func (o Opcode) String() string {
	if name, ok := opcodeNames[o]; ok {
		return name
	}
	return fmt.Sprintf("UNK(0x%02X)", byte(o))
}

func encodeOp(op Opcode) byte {
	return byte(op) ^ dispatchKey
}

func decodeOp(b byte) Opcode {
	return Opcode(b ^ dispatchKey)
}

type argEncoding int

const (
	argNone argEncoding = iota
	argI8
	argI16
	argI32
	argI64
)

func opArgEnc(op Opcode) argEncoding {
	switch op {
	case OpPush:
		return argI64
	case OpShl, OpShr, OpSwap:
		return argI8
	case OpJmp, OpJz, OpJnz:
		return argI32
	case OpLoad, OpStore, OpCall:
		return argI16
	default:
		return argNone
	}
}

func InstrSize(op Opcode) int {
	switch opArgEnc(op) {
	case argI64:
		return 9
	case argI32:
		return 5
	case argI16:
		return 3
	case argI8:
		return 2
	default:
		return 1
	}
}

func EncodeInstr(op Opcode, arg int64) []byte {
	size := InstrSize(op)
	buf := make([]byte, size)
	buf[0] = encodeOp(op)

	switch opArgEnc(op) {
	case argI64:
		binary.LittleEndian.PutUint64(buf[1:], uint64(arg))
	case argI32:
		binary.LittleEndian.PutUint32(buf[1:], uint32(arg))
	case argI16:
		binary.LittleEndian.PutUint16(buf[1:], uint16(arg))
	case argI8:
		buf[1] = byte(arg)
	}
	return buf
}

func DecodeInstr(code []byte, pc int) (Opcode, int64, int) {
	op := decodeOp(code[pc])
	size := InstrSize(op)

	var arg int64
	switch opArgEnc(op) {
	case argI64:
		arg = int64(binary.LittleEndian.Uint64(code[pc+1 : pc+9]))
	case argI32:
		arg = int64(binary.LittleEndian.Uint32(code[pc+1 : pc+5]))
	case argI16:
		arg = int64(binary.LittleEndian.Uint16(code[pc+1 : pc+3]))
	case argI8:
		arg = int64(code[pc+1])
	}
	return op, arg, size
}
