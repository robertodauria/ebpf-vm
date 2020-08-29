package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"io/ioutil"
	"log"

	"github.com/robertodauria/ebpf/pkg/vm"
	"github.com/yalue/elf_reader"
)

var (
	flagFilename   = flag.String("filename", "", "Path to the .o file")
	flagSection    = flag.String("section", "", "ELF section to execute")
	flagEndianness = flag.Bool("be", false, "Big Endian")
	flagVerbose    = flag.Bool("v", false, "Be verbose")

	// XXX: endianness should be inferred from the ELF file.
	endianness binary.ByteOrder
)

func main() {
	flag.Parse()
	if *flagFilename == "" || *flagSection == "" {
		log.Fatal("Please, specify -filename and -section")
	}
	raw, err := ioutil.ReadFile(*flagFilename)
	if err != nil {
		log.Fatal(err)
	}

	if *flagEndianness {
		endianness = binary.BigEndian
	} else {
		endianness = binary.LittleEndian
	}

	elf, err := elf_reader.ParseELFFile(raw)
	if err != nil {
		log.Fatal(err)
	}

	var found bool
	machine := new(vm.VM)
	machine.Endianness = endianness

	// Find the ELF section containing eBPF code.
	// This is not a fixed name, but depends on the kernel hook BPF code must
	// be attached to.
	for i := uint16(1); i < elf.GetSectionCount(); i++ {
		name, err := elf.GetSectionName(i)
		if err != nil {
			log.Fatal(err)
		}
		if name != *flagSection {
			continue
		}

		found = true
		program, err := elf.GetSectionContent(i)
		if err != nil {
			log.Fatal(err)
		}

		machine.Load(bytes.NewReader(program))
	}

	if !found {
		log.Fatalf("Cannot find section %s", *flagSection)
	}

	for {
		instruction, err := machine.Fetch()
		if err != nil {
			log.Fatal(err)
		}

		if *flagVerbose {
			machine.Disassemble(instruction)
		}

		if err := machine.Execute(instruction); err != nil {
			log.Fatal(err)
		}
	}

}
