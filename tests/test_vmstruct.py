import pytest

from vmrecover.vmstruct import parse_table


def _blob(code):
    blob = (0xB3B6A81B).to_bytes(4, "little")   # magic
    blob += (len(code)).to_bytes(4, "little")   # len_a
    blob += (0).to_bytes(4, "little")           # len_b
    blob += (0).to_bytes(4, "little")           # data_off
    blob += (2).to_bytes(4, "little")           # n_reloc
    blob += (0).to_bytes(4, "little")           # field_14 (unused)
    blob += (0x8D).to_bytes(8, "little")        # reloc[0]
    blob += (0x156).to_bytes(8, "little")       # reloc[1]
    blob += code
    return blob


def test_parse_header_and_relocs():
    code = b"\x01\x02\x03\x04"
    t = parse_table(_blob(code))
    assert t.magic == 0xB3B6A81B
    assert t.len_a == 4
    assert t.len_b == 0
    assert t.n_reloc == 2
    assert t.field_14 == 0
    assert t.relocs == [0x8D, 0x156]
    assert t.code == code


def test_too_short_raises():
    with pytest.raises(ValueError):
        parse_table(b"\x00" * 0x10)
