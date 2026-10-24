"""End-to-end demo: recover a hash IV a VM hides behind two-immediate XOR.

The bytecode below is a synthetic, minimal segment. It pushes eight SHA-256 IV
words, each split into two immediates and XORed at runtime — the exact trick a
real VM uses to keep ``strings`` and constant-scan from ever finding
``6a09e667``.

The (encrypted, key) pairs are what you read back out of the disassembly; the
folded values are the recovered plaintext. SHA-256's IV is public, so it makes
a good self-checking example: if the fold is correct, the words come out as the
standard constants.

Run:

    python examples/recover_sha256_iv.py
"""

from vmrecover.disasm import Disassembler
from vmrecover.xorconst import fold_constants

# A minimal opcode subset, enough for this demo.
TABLE = {
    0x07: ("push_i32", 4),
    0x08: ("push_i64", 8),
    0x0F: ("add32", 0),
    0x23: ("xor32", 0),
    0x24: ("xor64", 0),
    0x46: ("jmp", 4),
    0x4F: ("syscall", 4),
    0x50: ("halt", 0),
}

# SHA-256 IV, stored as (encrypted, key) pairs. The key is a running
# decrementing sequence; the plaintext is the standard IV.
PAIRS = [
    (0x95F78FD1, 0xFFFE69B6),
    (0x4499C730, 0xFFFE69B5),
    (0xC3909AC6, 0xFFFE69B4),
    (0x5AB19C89, 0xFFFE69B3),
    (0xAEF03BCD, 0xFFFE69B2),
    (0x64FB013D, 0xFFFE69B1),
    (0xE07DB01B, 0xFFFE69B0),
    (0xA41EA4B6, 0xFFFE69AF),
]


def build_code():
    code = b""
    for a, b in PAIRS:
        code += b"\x07" + a.to_bytes(4, "little")
        code += b"\x07" + b.to_bytes(4, "little")
        code += b"\x23"  # xor32
    code += b"\x50"  # halt
    return code


def main():
    code = build_code()
    d = Disassembler(TABLE)
    insns = d.decode(code)

    print("== disassembly (first 6 of %d insns) ==" % len(insns))
    for line in d.format(insns)[:6]:
        print("  " + line)
    print("  ...")

    hits = fold_constants(insns)
    print("\n== folded constants ==")
    for h in hits:
        print("  {a:08x} ^ {b:08x} = {value:08x}".format(**h))

    words = [h["value"] for h in hits]
    print("\nrecovered SHA-256 IV words:")
    print("  " + " ".join("%08X" % w for w in words))


if __name__ == "__main__":
    main()
