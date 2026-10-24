"""Dump an IDA address range as disassembly text.

Use this to export a VM interpreter's dispatch switch (or any range you need
to read opcode semantics from) into a plain ``.asm`` file that you can grep and
feed into your own decoder.

Edit START / END / OUT below, then run from inside IDA:

    File -> Script file... -> ida_dump_asm.py

or headless:

    idat64 -A -S"ida_dump_asm.py" target.so
"""

import ida_auto
import idc

START = 0x0      # <-- edit: range start (virtual address)
END = 0x0        # <-- edit: range end
OUT = r"dump.asm"  # <-- edit: output path


def main():
    ida_auto.auto_wait()
    lines = []
    ea = START
    while ea < END:
        try:
            line = idc.generate_disasm_line(ea, 0)
        except Exception:
            line = "0x%x: <err>" % ea
        lines.append("0x%05x: %s" % (ea, line))
        ea = idc.next_head(ea, END)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("DUMPED %d lines -> %s" % (len(lines), OUT))
    idc.qexit(0)


try:
    main()
except Exception as e:
    import traceback
    with open(OUT + ".err", "w", encoding="utf-8") as f:
        f.write(traceback.format_exc())
    idc.qexit(1)
