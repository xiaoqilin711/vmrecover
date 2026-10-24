from vmrecover.disasm import Disassembler
from vmrecover.xorconst import fold_constants

TABLE = {
    0x07: ("push_i32", 4),
    0x08: ("push_i64", 8),
    0x23: ("xor32", 0),
    0x24: ("xor64", 0),
    0x0f: ("add32", 0),
    0x50: ("halt", 0),
}


def test_fold_xor_reveals_sha256_iv():
    # push_i32 0x95f78fd1; push_i32 0xfffe69b6; xor32
    d = Disassembler(TABLE)
    code = (
        b"\x07" + (0x95F78FD1).to_bytes(4, "little")
        + b"\x07" + (0xFFFE69B6).to_bytes(4, "little")
        + b"\x23\x50"
    )
    hits = fold_constants(d.decode(code))
    assert len(hits) == 1
    assert hits[0]["symbol"] == "^"
    assert hits[0]["value"] == 0x6A09E667


def test_fold_add32():
    d = Disassembler(TABLE)
    code = b"\x07" + (1).to_bytes(4, "little") + b"\x07" + (2).to_bytes(4, "little") + b"\x0f\x50"
    hits = fold_constants(d.decode(code))
    assert hits[0]["symbol"] == "+"
    assert hits[0]["value"] == 3


def test_ignores_non_push_pattern():
    d = Disassembler(TABLE)
    code = b"\x07" + (1).to_bytes(4, "little") + b"\x50"
    assert fold_constants(d.decode(code)) == []
