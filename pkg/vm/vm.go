package vm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The following constants define the machine
const (
	StackSize    = 1 << 9
	NumRegisters = 11
)

// This list of constants defines the opcodes.
const (
	// ***********************
	// Instruction classes
	// ***********************
	BPFLD    = 0x00
	BPFLDX   = 0x01
	BPFST    = 0x02
	BPFSTX   = 0x03
	BPFALU   = 0x04
	BPFJMP   = 0x05
	BPFJMP32 = 0x06
	BPFALU64 = 0x07

	// **********************************************
	// BPF_ALU/ BPF_JMP source operands
	// **********************************************
	BPFK = 0x00 // Use src register as source operand
	BPFX = 0x08 // Use 32-bit imm as source operand

	// **********************************************
	// BPF_ALU/BPF_ALU64 instruction codes
	// **********************************************
	BPFADD  = 0x00
	BPFSUB  = 0x10
	BPFMUL  = 0x20
	BPFDIV  = 0x30
	BPFOR   = 0x40
	BPFAND  = 0x50
	BPFLSH  = 0x60
	BPFRSH  = 0x70
	BPFNEG  = 0x80
	BPFMOD  = 0x90
	BPFXOR  = 0xa0
	BPFMOV  = 0xb0 /* eBPF only: mov reg to reg */
	BPFARSH = 0xc0 /* eBPF only: sign extending shift right */
	BPFEND  = 0xd0 /* eBPF only: endianness conversion */

	// **********************************************
	// BPF_JMP/BPF_JMP32 instruction codes
	// **********************************************
	BPFJA   = 0x00 /* BPF_JMP only */
	BPFJEQ  = 0x10
	BPFJGT  = 0x20
	BPFJGE  = 0x30
	BPFJSET = 0x40
	BPFJNE  = 0x50 /* eBPF only: jump != */
	BPFJSGT = 0x60 /* eBPF only: signed '>' */
	BPFJSGE = 0x70 /* eBPF only: signed '>=' */
	BPFCALL = 0x80 /* eBPF BPF_JMP only: function call */
	BPFEXIT = 0x90 /* eBPF BPF_JMP only: function return */
	BPFJLT  = 0xa0 /* eBPF only: unsigned '<' */
	BPFJLE  = 0xb0 /* eBPF only: unsigned '<=' */
	BPFJSLT = 0xc0 /* eBPF only: signed '<' */
	BPFJSLE = 0xd0 /* eBPF only: signed '<=' */

	// ***********************
	//  ALU instructions
	// ***********************
	OpcodeADDIMM = BPFADD | BPFK | BPFALU64 // 0x07
	OpcodeADDSRC = 0x0f
	OpcodeSUBIMM = 0x17
	OpcodeSUBSRC = 0x1f

	// TODO: a bunch of instructions.

	OpcodeLSHIMM  = 0x67
	OpcodeLSHSRC  = 0x6f
	OpcodeRSHIMM  = 0x77
	OpcodeRSHSRC  = 0x7f
	OpcodeARSHIMM = 0xc7

	OpcodeMOVDSTIMM = 0xb7
	OpcodeMOVDSTSRC = 0xbf

	// TODO: 32-bit instructions.

	// ***********************
	// Byteswap instructions
	// ***********************
	//
	// Opcode	Mnemonic	           Pseudocode
	// 0xd4   (imm == 16)	le16 dst	dst = htole16(dst)
	// 0xd4   (imm == 32)	le32 dst	dst = htole32(dst)
	// 0xd4   (imm == 64)	le64 dst	dst = htole64(dst)
	// 0xdc   (imm == 16)	be16 dst	dst = htobe16(dst)
	// 0xdc   (imm == 32)	be32 dst	dst = htobe32(dst)
	// 0xdc   (imm == 64)	be64 dst	dst = htobe64(dst)

	OpcodeLE = 0xd4
	OpcodeBE = 0xdc

	// ***********************
	// Memory instructions
	// ***********************

	// OpcodeLDDW extends into the next instruction as it loads a 64-bit word
	// while the immediate can only contain 32 bits.
	// The next instruction will have opcode, dst/src and offset set to zero.
	OpcodeLDDW = 0x18

	// See kernel documentation for the following.
	OpcodeLDABSW  = 0x20
	OpcodeLDABSH  = 0x28
	OpcodeLDABSB  = 0x30
	OpcodeLDABSDW = 0x38
	OpcodeLDINDW  = 0x40
	OpcodeLDINDH  = 0x48
	OpcodeLDINDB  = 0x50
	OpcodeLDINDDW = 0x58

	OpcodeLDXW  = 0x61
	OpcodeLDXH  = 0x69
	OpcodeLDXB  = 0x71
	OpcodeLDXDW = 0x79
	OpcodeSTW   = 0x62
	OpcodeSTH   = 0x6a
	OpcodeSTB   = 0x72
	OpcodeSTDW  = 0x7a
	OpcodeSTXW  = 0x63
	OpcodeSTXH  = 0x6b
	OpcodeSTXB  = 0x73
	OpcodeSTXDW = 0x7b

	// ***********************
	// Branch instructions
	// ***********************

	// TODO: branch instructions.

	OpcodeCALL = 0x85
	OpcodeEXIT = 0x95
)

// Word is a 64-bit word.
type Word uint64

// VM is a eBPF virtual machine.
type VM struct {
	Endianness binary.ByteOrder
	GPR        [NumRegisters]uint64 // general purpose registers + frame pointer
	Stack      [StackSize]uint8     // stack
	Program    io.Reader            // instructions
	PC         int                  // program counter
}

// Load sets the vm.Program to the specified reader and
// initializes the R10 register to the top of the stack.
func (vm *VM) Load(section io.Reader) {
	vm.Program = section
	vm.GPR[10] = StackSize
}

// Fetch reads an Instruction from the vm.Program reader.
func (vm *VM) Fetch() (*Instruction, error) {
	var instr Instruction
	err := binary.Read(vm.Program, vm.Endianness, &instr)
	if err != nil {
		return nil, err
	}

	// TODO: Handle multi-word instructions.

	vm.PC++
	return &instr, nil
}

func (vm *VM) store(data []byte, addr uint64) {
}

func (vm *VM) Execute(instr *Instruction) error {
	src := vm.getSrc(instr)
	dst := vm.getDst(instr)

	switch instr.Opcode {
	case OpcodeEXIT:
		return errors.New("exit")
	case OpcodeSTXDW: // stxdw [dst+off], src
		b := make([]byte, 8)
		vm.Endianness.PutUint64(b, vm.getRegister(src))
		addr := vm.getRegister(dst)
		copy(vm.Stack[int64(addr)+int64(instr.Offset):], b)
	case OpcodeSTXH: // stxh [dst+off], src
		b := make([]byte, 2)
		vm.Endianness.PutUint16(b, uint16(vm.getRegister(src)))
		addr := vm.getRegister(dst)
		copy(vm.Stack[int64(addr)+int64(instr.Offset):], b)
	case OpcodeLDXH: // ldxh dst, [src+off]
		start := int64(vm.getRegister(src)) + int64(instr.Offset)
		value := vm.Endianness.Uint16(vm.Stack[start : start+2])
		vm.setRegister(dst, uint64(value))
	case OpcodeMOVDSTIMM: // mov dst, imm
		vm.setRegister(dst, uint64(instr.Immediate))
	case OpcodeLSHIMM: // lsh dst, imm
		value := vm.getRegister(vm.getDst(instr))
		vm.setRegister(dst, value<<instr.Immediate)
	case OpcodeRSHIMM: // rsh dst, imm
		value := vm.getRegister(vm.getDst(instr))
		vm.setRegister(dst, value>>instr.Immediate)
	case OpcodeARSHIMM: // arsh dst, imm
		value := vm.getRegister(vm.getDst(instr))

		// Using a signed int64 forces Go to do an arithmetic shift and keep
		// the value's sign.
		vm.setRegister(dst, uint64((int64(value) >> instr.Immediate)))
	}

	//vm.debug()
	return nil
}

func (vm *VM) Disassemble(i *Instruction) {
	switch i.Opcode {
	case OpcodeSTXDW:
		fmt.Printf("%-6s [r%d%+d], r%d\n", "stxdw", vm.getDst(i), i.Offset, vm.getSrc(i))
	case OpcodeSTXH: // stxh [dst+off], src
		fmt.Printf("%-6s [r%d%+d], r%d\n", "stxh", vm.getDst(i), i.Offset, vm.getSrc(i))
	case OpcodeLDXH: // ldxh dst, [src+off]
		fmt.Printf("%-6s r%d, [r%d%+d]\n", "ldxh", vm.getDst(i), vm.getSrc(i), i.Offset)
	case OpcodeMOVDSTIMM:
		fmt.Printf("%-6s r%d, %d\n", "mov", vm.getDst(i), i.Immediate)
	case OpcodeLSHIMM:
		fmt.Printf("%-6s r%d, %d\n", "lsh", vm.getDst(i), i.Immediate)
	case OpcodeRSHIMM:
		fmt.Printf("%-6s r%d, %d\n", "rsh", vm.getDst(i), i.Immediate)
	case OpcodeARSHIMM:
		fmt.Printf("%-6s r%d, %d\n", "arsh", vm.getDst(i), i.Immediate)
	case OpcodeCALL:
		fmt.Printf("%-6s %d\n", "call", i.Immediate)
	case OpcodeEXIT:
		fmt.Printf("exit\n")
	default:
		fmt.Printf("todo (%x)\n", i.Opcode)
	}
}

func (vm *VM) getSrc(i *Instruction) uint8 {
	switch vm.Endianness {
	case binary.LittleEndian:
		return i.DstSrc >> 4
	default:
		return i.DstSrc & 0b0000_1111
	}
}

func (vm *VM) getDst(i *Instruction) uint8 {
	switch vm.Endianness {
	case binary.LittleEndian:
		return i.DstSrc & 0b0000_1111
	default:
		return i.DstSrc >> 4
	}
}

func (vm *VM) getRegister(i uint8) uint64 {
	if i >= NumRegisters {
		panic("Invalid register")
	}

	return vm.GPR[i]
}

func (vm *VM) setRegister(i uint8, val uint64) {
	if i >= NumRegisters {
		panic("Invalid register")
	}

	vm.GPR[i] = val
}

func (vm *VM) debug() {
	fmt.Println("Registers:")
	for i, val := range vm.GPR {
		fmt.Printf("R%d = %#x, ", i, val)
	}
	fmt.Println()
	fmt.Println("Stack")
	kk := vm.Stack[StackSize-50 : StackSize]

	fmt.Printf("%+v\n", kk)
}
