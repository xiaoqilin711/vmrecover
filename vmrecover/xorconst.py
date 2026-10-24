"""Recover constants hidden by two-immediate folding.

Obfuscated VMs commonly hide magic constants (hash IVs, CRC tables, round
constants) by splitting each one into two immediates and XORing or adding them
at runtime. A plain constant scan then finds nothing — the value only ever
exists as the *result* of an instruction, never as a stored byte.

This pass detects the ``push_imm A; push_imm B; <op>`` pattern in decoded
instructions and folds it back to ``A op B``. It is exactly what a black-box
run cannot do: emulation sees only inputs and outputs, never the intermediate
immediates that reconstruct the constant.
"""

from typing import Dict, List, Optional, Tuple

from .disasm import Insn

_PUSH = {"push_i32", "push_i64"}

# opcode mnemonic -> (display symbol, bit width)
_OPS: Dict[str, Tuple[str, int]] = {
    "xor32": ("^", 32),
    "xor64": ("^", 64),
    "add32": ("+", 32),
    "add64": ("+", 64),
    "sub32": ("-", 32),
    "sub64": ("-", 64),
}


def fold_constants(
    insns: List[Insn],
    ops: Optional[Dict[str, Tuple[str, int]]] = None,
) -> List[dict]:
    """Detect ``push_imm A; push_imm B; <op>`` and fold to ``A op B``.

    ``ops`` optionally overrides the folding opcodes, mapping mnemonic ->
    ``(symbol, bit_width)``. Returns a list of dicts with keys ``offset`` (of
    the op), ``op``, ``symbol``, ``a``, ``b`` and ``value`` (unsigned).
    """
    table = _OPS if ops is None else ops
    results = []
    for i in range(len(insns) - 2):
        a, b, op = insns[i], insns[i + 1], insns[i + 2]
        if a.mnemonic not in _PUSH or b.mnemonic not in _PUSH:
            continue
        if a.imm is None or b.imm is None:
            continue
        entry = table.get(op.mnemonic)
        if entry is None:
            continue
        symbol, width = entry
        mask = (1 << width) - 1
        av, bv = a.imm & mask, b.imm & mask
        if symbol == "^":
            value = av ^ bv
        elif symbol == "+":
            value = (av + bv) & mask
        else:  # "-"
            value = (av - bv) & mask
        results.append(
            {
                "offset": op.offset,
                "op": op.mnemonic,
                "symbol": symbol,
                "a": av,
                "b": bv,
                "value": value,
            }
        )
    return results
