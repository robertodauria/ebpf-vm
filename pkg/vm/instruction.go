package vm

import "fmt"

type Instruction struct {
	Opcode    uint8
	DstSrc    uint8
	Offset    int16
	Immediate int32
}

func (i *Instruction) String() string {
	return fmt.Sprintf("opcode: %#02x, dst: %d, src: %d, offset: %d, imm: %d",
		i.Opcode, i.DstSrc&0b0000_1111, i.DstSrc>>4, i.Offset, i.Immediate)
}
