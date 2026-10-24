"""Structured disassembler for custom VM bytecode.

This is the semantic-recovery layer above a bare opcode table: it decodes a
bytecode blob into structured instructions and annotates relocated function
pointers, so downstream passes (constant folding, control-flow reading) can
work on *meaning* instead of raw bytes.

A black-box emulator never needs any of this — it just runs the bytes and
compares outputs. This module exists for the opposite route: read the
interpreter's dispatch switch once, recover the opcode table, then read the
bytecode directly without ever executing it.
"""

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class Insn:
    """One decoded VM instruction."""

    offset: int                 # byte offset of the opcode within the code segment
    opcode: int                 # raw opcode byte
    mnemonic: str               # resolved mnemonic ("db" for unknown bytes)
    ilen: int = 0               # immediate length in bytes (0 / 4 / 8)
    imm: Optional[int] = None   # decoded immediate (signed for i32, unsigned for i64)
    reloc: bool = False         # True if this 8-byte immediate is a relocated fn pointer


class Disassembler:
    """Linear-sweep decoder driven by an opcode table.

    ``table`` maps ``opcode -> (mnemonic, immediate_length)``.
    ``immediate_length`` is the number of bytes (0, 4 or 8) that follow the
    opcode and encode its operand. The table is binary-specific; you recover it
    from the interpreter's dispatch switch (see the case study).
    """

    def __init__(self, table: Dict[int, Tuple[str, int]]):
        self.table = table

    def decode(self, code: bytes, relocs: tuple = ()) -> List[Insn]:
        """Decode ``code`` into structured instructions.

        ``relocs`` is an iterable of byte offsets (into ``code``) that mark the
        immediate of an 8-byte push as a relocated function pointer.
        """
        reloc_set = set(relocs)
        out: List[Insn] = []
        i, n = 0, len(code)
        while i < n:
            op = code[i]
            entry = self.table.get(op)
            if entry is None:
                out.append(Insn(offset=i, opcode=op, mnemonic="db"))
                i += 1
                continue
            mnemonic, ilen = entry
            raw = code[i + 1 : i + 1 + ilen] if ilen else b""
            imm = None
            if ilen == 4 and len(raw) == 4:
                imm = struct.unpack("<i", raw)[0]
            elif ilen == 8 and len(raw) == 8:
                imm = struct.unpack("<Q", raw)[0]
            is_reloc = ilen == 8 and (i + 1) in reloc_set
            out.append(
                Insn(
                    offset=i,
                    opcode=op,
                    mnemonic=mnemonic,
                    ilen=ilen,
                    imm=imm,
                    reloc=is_reloc,
                )
            )
            i += 1 + ilen
        return out

    @staticmethod
    def format(insns: List[Insn]) -> List[str]:
        """Render decoded instructions as assembly-style text lines."""
        return [_format_insn(ins) for ins in insns]


def _format_insn(ins: Insn) -> str:
    off = "{:04x}:".format(ins.offset)
    if ins.mnemonic == "db":
        return "{} db 0x{:02x}  <unknown>".format(off, ins.opcode)
    if ins.ilen == 0:
        return "{}{}".format(off, ins.mnemonic)
    mne = "{:<16}".format(ins.mnemonic)
    if ins.mnemonic in ("brz", "brnz", "jmp"):
        target = (ins.offset + 5 + ins.imm) & 0xFFFF
        return "{} {} -> {:04x}".format(off, mne, target)
    if ins.mnemonic == "syscall":
        tag = "  ; RELOC -> fn ptr" if ins.reloc else ""
        return "{} {} #{}{}".format(off, mne, ins.imm, tag)
    if ins.ilen == 8:
        tag = "  ; RELOC -> fn ptr" if ins.reloc else ""
        return "{} {} 0x{:x}{}".format(off, mne, ins.imm, tag)
    return "{} {} {} (0x{:x})".format(off, mne, ins.imm, ins.imm & 0xFFFFFFFF)
