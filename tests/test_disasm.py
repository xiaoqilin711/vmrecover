from vmrecover.disasm import Disassembler

TABLE = {
    0x07: ("push_i32", 4),
    0x08: ("push_i64", 8),
    0x50: ("halt", 0),
}


def test_decode_offsets_and_immediates():
    d = Disassembler(TABLE)
    code = b"\x07" + (0x12345678).to_bytes(4, "little") + b"\x50"
    insns = d.decode(code)
    assert [i.mnemonic for i in insns] == ["push_i32", "halt"]
    assert insns[0].offset == 0
    assert insns[0].ilen == 4
    assert insns[0].imm & 0xFFFFFFFF == 0x12345678
    assert insns[1].offset == 5


def test_reloc_annotation():
    d = Disassembler(TABLE)
    code = b"\x08" + (0x240).to_bytes(8, "little") + b"\x50"
    insns = d.decode(code, relocs=(1,))
    assert insns[0].reloc is True
    assert insns[0].ilen == 8


def test_unknown_byte_becomes_db():
    d = Disassembler(TABLE)
    insns = d.decode(b"\x99\x50")
    assert insns[0].mnemonic == "db"
    assert insns[1].mnemonic == "halt"


def test_format_has_reloc_marker():
    d = Disassembler(TABLE)
    code = b"\x08" + (0x240).to_bytes(8, "little")
    insns = d.decode(code, relocs=(1,))
    line = d.format(insns)[0]
    assert "RELOC" in line
