NXTool
======

NXTool is a command-line tool to manipulate Nintendo Switch NRO and NRR files. It parses and prints the headers, and transforms NRO files into ELF, making it easier to disassemble.

## Build

### Linux/OSX

Simply `make` the program. On OSX, you'll need to make sure you have Xcode command line tools installed. On linux, you'll need a working `gcc` toolchain.

## Usage

```
nxtool (c) Dazzozo
Built: 16:58:14 Mar 15 2017

Usage: ./nxtool [options...] <file>
Options:
  -i, --info            Show file info.
                             This is the default action.
  -x, --extract         Extract data from file.
                             This is also the default action.
  -p, --plain           Extract data without decrypting.
  -r, --raw             Keep raw data, don't unpack.
  -k, --keyset=file     Specify keyset file.
  -v, --verbose         Give verbose output.
  -y, --verify          Verify hashes and signatures.
  --showkeys            Show the keys being used.
  -t, --intype=type     Specify input file type [modf, nro, nrr]

MOD options:
  --elf=file            Specify ELF file path.
```

To transform an NRO into an ELF :

`./nxtool --elf=file.elf file.nro`
