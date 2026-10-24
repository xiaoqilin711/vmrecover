"""vmrecover — static recovery of algorithms hidden inside custom VM bytecode.

When a native binary moves its real logic into a custom stack-machine bytecode
interpreter, the usual options are to emulate the whole thing (unidbg) or to
hook it dynamically. This package is for the third route: read the interpreter
once, recover the opcode table, then disassemble the bytecode directly and
recover *what it actually computes* — constants, structure and post-processing
that a black-box run can never expose.

Every module is site-agnostic: no hardcoded opcodes, offsets, magic values,
package names or keys.
"""

from .disasm import Disassembler, Insn
from .vmstruct import Table, parse_table
from .xorconst import fold_constants

__version__ = "0.1.0"

__all__ = [
    "Disassembler",
    "Insn",
    "Table",
    "parse_table",
    "fold_constants",
]
