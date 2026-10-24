"""Parse the container format of a VM bytecode table.

Many VM protections store their bytecode in a table with a fixed header (magic,
segment lengths, relocation count, one unused word) followed by a relocation
table and the code segment. Parsing that header is the first concrete step
before disassembly.
"""

import struct
from dataclasses import dataclass
from typing import List


@dataclass
class Table:
    magic: int
    len_a: int
    len_b: int
    data_off: int
    n_reloc: int
    field_14: int   # 6th header word; 0 in every observed table, purpose unknown
    relocs: List[int]
    code: bytes


def parse_table(blob: bytes) -> Table:
    """Parse a VM bytecode table.

    Layout: ``magic(4) len_a(4) len_b(4) data_off(4) n_reloc(4) field_14(4)``,
    then ``n_reloc`` 8-byte relocation offsets, then the code segment
    (``len_a + len_b`` bytes).
    """
    if len(blob) < 0x18:
        raise ValueError("blob too short for a table header (need 0x18 bytes)")
    magic, len_a, len_b, data_off, n_reloc, field_14 = struct.unpack_from(
        "<IIIIII", blob, 0
    )
    reloc_start = 0x18
    reloc_end = reloc_start + n_reloc * 8
    relocs = [
        struct.unpack_from("<Q", blob, reloc_start + i * 8)[0]
        for i in range(n_reloc)
    ]
    code_start = reloc_end
    code_end = code_start + len_a + len_b
    return Table(
        magic=magic,
        len_a=len_a,
        len_b=len_b,
        data_off=data_off,
        n_reloc=n_reloc,
        field_14=field_14,
        relocs=relocs,
        code=blob[code_start:code_end],
    )
