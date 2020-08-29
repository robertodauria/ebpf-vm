# eBPF-VM

This is an implementation of an eBPF virtual machine in Golang.

It's currently still incomplete and will likely be for a while. Here's what works:

- Reading from an ELF object file, as long as you specify the ELF section to
read with `-section`
- Endianness can be set with `-be` for big-endian (default is little-endian)
- 10 registers (from R0 to R9) are available, with R10 being the frame pointer
- 512-bytes stack
- Verbose mode (with `-v`) will print each instruction as it's executed
- Debug mode is also available, which outputs the registers and memory state after each instruction -- but you need to uncomment it in the code :)
- Some (*) instructions are implemented

(*): _Just the ones that are used by the test .o files -- and not even all of them._

This is a work in progress. If you feel brave, you can build it and test it with something like:

```bash
go build -v ./cmd/vm
./vm -filename testdata/call.o -section .text -v
```
