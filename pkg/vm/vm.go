package vm

import (
	"errors"
	"fmt"
)

// The following constants define the machine
const (
	MemorySize   = 1 << 9
	StackSize    = MemorySize / 8
	NumRegisters = 11
)

const (
	OpcodeSTXDW     = 0x7b
	OpcodeMOVDSTIMM = 0xb7
	OpcodeMOVDSTSRC = 0xbf
	OpcodeCALL      = 0x85
	OpcodeEXIT      = 0x95
)

// Word is a 64-bit word.
type Word uint64

// VM is a eBPF virtual machine.
type VM struct {
	GPR   [NumRegisters]Word // general purpose registers
	Stack [StackSize]Word    // stack
	Instr []*Instruction     // instructions
	PC    int                // program counter
}

func (vm *VM) Fetch() (*Instruction, error) {
	if vm.PC == len(vm.Instr) {
		return nil, errors.New("notte!")
	}
	instr := vm.Instr[vm.PC]
	vm.PC++
	return instr, nil
}

func (vm *VM) Execute(instr *Instruction) error {
	return nil
}

func (vm *VM) Disassemble(i *Instruction) {
	dst := i.DstSrc & 0b0000_1111
	src := i.DstSrc >> 4
	switch i.Opcode {
	case OpcodeSTXDW:
		fmt.Printf("stxdw [r%d %+d], r%d\n", dst, i.Offset, src)
	case OpcodeMOVDSTIMM:
		fmt.Printf("mov r%d, %d\n", dst, i.Immediate)
	case OpcodeMOVDSTSRC:
		fmt.Printf("mov r%d, r%d\n", dst, src)
	case OpcodeCALL:
		fmt.Printf("call %d\n", i.Immediate)
	case OpcodeEXIT:
		fmt.Printf("exit\n")
	default:
		fmt.Printf("todo\n")
	}
}
