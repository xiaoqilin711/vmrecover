"""Command-line entry point for vmrecover."""

import argparse
import json
import sys
from pathlib import Path

from .disasm import Disassembler
from .vmstruct import parse_table
from .xorconst import fold_constants


def _load_table(path: str) -> dict:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {int(k, 16): (v[0], int(v[1])) for k, v in raw.items()}


def _load_blob(path: str) -> bytes:
    return Path(path).read_bytes()


def _resolve_blob(args) -> bytes:
    if getattr(args, "hex", None):
        return bytes.fromhex(args.hex)
    if getattr(args, "blob", None):
        return _load_blob(args.blob)
    raise SystemExit("error: provide either BLOB or --hex")


def cmd_parse(args):
    t = parse_table(_load_blob(args.blob))
    print("magic     = 0x{:08x}".format(t.magic))
    print("len_a     = {}".format(t.len_a))
    print("len_b     = {}".format(t.len_b))
    print("data_off  = {}".format(t.data_off))
    print("n_reloc   = {}".format(t.n_reloc))
    print("relocs    = [{}]".format(", ".join("0x{:x}".format(r) for r in t.relocs)))
    print("code_len  = {} bytes".format(len(t.code)))


def cmd_disasm(args):
    relocs = tuple(int(x, 16) for x in (args.relocs.split(",") if args.relocs else []))
    d = Disassembler(_load_table(args.table))
    insns = d.decode(_resolve_blob(args), relocs)
    print("\n".join(d.format(insns)))


def cmd_fold(args):
    d = Disassembler(_load_table(args.table))
    insns = d.decode(_resolve_blob(args))
    for hit in fold_constants(insns):
        print(
            "{:04x}: {:<6} {:08x} {} {:08x} = {:08x}".format(
                hit["offset"],
                hit["op"],
                hit["a"],
                hit["symbol"],
                hit["b"],
                hit["value"],
            )
        )


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="vmrecover",
        description="Recover algorithms hidden inside custom VM bytecode.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("parse", help="parse a VM bytecode table header")
    q.add_argument("blob")
    q.set_defaults(func=cmd_parse)

    q = sub.add_parser("disasm", help="disassemble a bytecode segment")
    q.add_argument("blob", nargs="?", help="bytecode blob file")
    q.add_argument("--hex", help="bytecode as a hex string (alternative to BLOB)")
    q.add_argument("--table", required=True, help="opcode table JSON")
    q.add_argument("--relocs", help="comma-separated relocation offsets (hex)")
    q.set_defaults(func=cmd_disasm)

    q = sub.add_parser("fold", help="fold two-immediate constants back to values")
    q.add_argument("blob", nargs="?", help="bytecode blob file")
    q.add_argument("--hex", help="bytecode as a hex string (alternative to BLOB)")
    q.add_argument("--table", required=True, help="opcode table JSON")
    q.set_defaults(func=cmd_fold)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
