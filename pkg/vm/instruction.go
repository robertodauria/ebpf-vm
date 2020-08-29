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
// Some instructions can be called with immediates larger than 32 bits.
// These are provided with subsequent 64-bit words where the opcode, dst, src
// and offset are all zero.
// e.g.
//    opcode  dst+src     offset         immediate
// 1: [0x7b]  [0x1a]   [0x00 0x01] [0x01 0x02 0x03 0x04]
// 2: [0x00]  [0x00]   [0x00 0x00] [0x05 0x06 0x07 0x08]
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
