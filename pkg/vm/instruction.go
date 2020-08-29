package vm

import "fmt"

// Instruction represents a eBPF instruction.
//
// msb                                                        lsb
// +------------------------+----------------+----+----+--------+
// |immediate               |offset          |src |dst |opcode  |
// +------------------------+----------------+----+----+--------+
//
// From least significant to most significant bit:
// 8 bit opcode
// 4 bit destination register (dst)
// 4 bit source register (src)
// 16 bit offset
// 32 bit immediate (imm)
//
type Instruction struct {
	// Opcode is the instruction's opcode.
	Opcode uint8

	// DstSrc contains both destination and source registers.
	// Dst occupies the 4 LSB, Src occupies the 4 MSB.
	DstSrc uint8

	// Offset is the offset for the current instruction.
	Offset int16

	// Immediate is the immediate value for the instruction
	Immediate int32
}

func (i *Instruction) String() string {
	return fmt.Sprintf("opcode: %#02x, dstsrc: %b, offset: %d, imm: %d",
		i.Opcode, i.DstSrc, i.Offset, i.Immediate)
}
