# vmrecover

[![CI](https://github.com/xiaoqilin711/vmrecover/actions/workflows/ci.yml/badge.svg)](https://github.com/xiaoqilin711/vmrecover/actions/workflows/ci.yml)

**Semantic recovery tooling for bytecode VMs — disassemble a custom VM's bytecode and fold out the constants it hides.**

[English](README.md) | [中文](README.zh-CN.md)

> **The proof, in one line:** where black-box emulation (unidbg) could only watch a protected signing library's VM from the outside and never match standard SHA-256, reading its bytecode directly recovered all 8 hidden IV words — **8/8 signature match**.

| Route | What it sees | Result |
|-------|--------------|--------|
| unidbg emulation | VM inputs/outputs only | no match against standard SHA-256 |
| **vmrecover** | instruction immediates | recovered 8 SHA-256 IV words, **8/8 match** |

A common anti-analysis trick in protected native binaries is to move the interesting algorithm into a custom bytecode VM: the real hash/cipher isn't a normal function, it's self-decrypting bytecode run by a hand-written interpreter. Black-box approaches (unidbg emulation, runtime hooking) see only the VM's inputs and outputs — never the obfuscated constants that live *inside instruction immediates*.

`vmrecover` is the "after you've read the interpreter" toolkit: given an opcode table you recovered by hand, it disassembles the bytecode into structured instructions, parses the table header (including an easy-to-miss field), and folds out constants hidden behind two-immediate arithmetic.

## Why this exists

Two findings from a real reverse-engineering project drove this:

1. **Constants hidden in immediates are invisible to black-box.** A SHA-256 IV was split into `push A; push B; xor` pairs (`0x95f78fd1 ^ 0xfffe69b6 == 0x6a09e667`). The complete value never exists in runtime memory, so no hook or emulator can observe it — only disassembly + constant folding can.
2. **A tiny header field silently corrupts everything.** The bytecode-table header is six 32-bit words, not five; missing the always-zero word at `0x14` misaligns the entire relocation table.

The full story — including the "hard-reverse vs unidbg" comparison — is in [docs/case-study.md](docs/case-study.md).

## Features

- **`vmrecover.disasm`** — disassemble bytecode into structured `Insn` objects (offset, opcode, mnemonic, instruction length, immediate, relocation annotation, jump targets).
- **`vmrecover.xorconst`** — recognize `push_imm A; push_imm B; <op>` and fold to `A op B`, recovering constants hidden by two-immediate arithmetic (`xor`, `add`, `sub`; 32- and 64-bit).
- **`vmrecover.vmstruct`** — parse a VM bytecode-table header (six fields) and its relocation table.
- **CLI** — `parse`, `disasm`, and `fold` subcommands.
- **Zero runtime dependencies**; `pytest` only for the test extra.

## Install

```bash
git clone https://github.com/<user>/vmrecover.git
cd vmrecover
pip install -e .
```

## Quick start

```bash
# disassemble bytes with a JSON opcode table
vmrecover disasm --table examples/opcode_table.json --hex "07d18ff79507b669feff2350"

# fold constants hidden behind two-immediate arithmetic
python examples/recover_sha256_iv.py
```

Or as a library:

```python
from vmrecover.disasm import Disassembler
from vmrecover.xorconst import fold_constants

table = {0x07: ("push_i32", 4), 0x23: ("xor32", 0), 0x50: ("halt", 0)}
code = b"\x07" + (0x95F78FD1).to_bytes(4, "little") \
     + b"\x07" + (0xFFFE69B6).to_bytes(4, "little") \
     + b"\x23\x50"

insns = Disassembler(table).decode(code)
for hit in fold_constants(insns):
    print(f"{hit['a']:08x} ^ {hit['b']:08x} = {hit['value']:08x}")
# 95f78fd1 ^ fffe69b6 = 6a09e667
```

## Architecture

```
bytecode blob ──> vmstruct.parse_table ──> Table (header + relocs + code)
                                              │
                                              v
opcode table (JSON/py) ──> disasm.Disassembler.decode ──> [Insn]
                                              │
                                              v
                              xorconst.fold_constants ──> recovered constants
```

```
vmrecover/
├── disasm.py     # Insn dataclass + Disassembler (decode/format)
├── xorconst.py   # fold_constants: push A; push B; op -> A op B
├── vmstruct.py   # Table + parse_table (six-field header, relocs)
└── cli.py        # parse / disasm / fold subcommands
```

## Honest boundaries

- **It does not recover the instruction set for you.** Opcode semantics are binary-specific and must be read by hand from the interpreter's dispatch switch. `vmrecover` is the layer you feed *after* that reading.
- **It does not emulate.** No bytecode execution; disassembly and semantic recognition only. Dynamic verification (Frida differential testing, unidbg cross-check) is still required to confirm a conclusion.
- **One known VM shape.** `vmstruct` encodes the header layout of *the* VM encountered in the case study (six 32-bit words, relocation table at `0x18`). Other VMs differ; the parsing logic is a reference, not a universal parser.

## Documentation

- [Case study (English)](docs/case-study.md) / [案例研究（中文）](docs/case-study.zh-CN.md) — anonymized write-up of the real project, including the hard-reverse vs unidbg decision and the three constant-hiding tricks found.
- [examples/recover_sha256_iv.py](examples/recover_sha256_iv.py) — end-to-end demo: recover a SHA-256 IV hidden behind two-immediate XOR.
- [tools/ida_dump_asm.py](tools/ida_dump_asm.py) — dump an IDA address range (e.g. a VM interpreter's dispatch switch) to disassembly text.

## Development

```bash
pip install -e ".[test]"
pytest
```

## License

[MIT](LICENSE)
