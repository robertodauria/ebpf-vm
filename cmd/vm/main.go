package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/robertodauria/ebpf/pkg/vm"
	"github.com/yalue/elf_reader"
)

func main() {
	raw, e := ioutil.ReadFile("call.o")
	if e != nil {
		fmt.Printf("Failed reading /bin/bash: %s\n", e)
		return
	}
	elf, e := elf_reader.ParseELFFile(raw)
	if e != nil {
		fmt.Printf("Failed parsing ELF file: %s\n", e)
		return
	}

	fmt.Println(elf.GetSectionName(2))
	program, err := elf.GetSectionContent(2)

	if err != nil {
		fmt.Printf("Failed reading .text: %s\n", err)
	}

	// Read all the instructions.
	var instructions = make([]*vm.Instruction, 0, len(program)/8)

	pbuffer := bytes.NewBuffer(program)
	for pbuffer.Len() > 0 {
		instr := &vm.Instruction{}
		instrBytes := pbuffer.Next(8)
		err := binary.Read(bytes.NewReader(instrBytes), binary.LittleEndian, instr)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Decoded instruction: %+v\n", instr)
		instructions = append(instructions, instr)
	}

	machine := new(vm.VM)
	machine.Instr = instructions

	// Fetch/Execute loop.
	for {
		instr, err := machine.Fetch()
		if err != nil {
			log.Println(err)
			break
		}
		if err = machine.Execute(instr); err != nil {
			log.Println(err)
			break
		}

		machine.Disassemble(instr)
	}

}
