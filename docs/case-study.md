# Case Study: Reversing a VM That Hides SHA-256 — Without unidbg

[English](case-study.md) | [中文](case-study.zh-CN.md)

> **Anonymized.** This write-up intentionally omits the vendor name, package name, real offsets, keys, and sample values. The target is the native signing library (a single ARM64 `.so`) of a large e-commerce app. All addresses and constants below are illustrative, not real.

## TL;DR

Inside a native signing library, the real hash transform isn't a normal function — it's **self-decrypting bytecode** running on an **85-instruction custom stack machine**. Worse: the SHA-256 initialization vector is split into "two immediates XORed at runtime", and the post-processing constants are buried at the tail of the bytecode — so `strings` can't find the magic values, and black-box comparison never matches standard SHA-256.

Facing the same target, there are two routes:

- **Route A (common)**: use unidbg to emulate the `.so` with hand-patched env, hook intermediate values, and guess the algorithm. Fast — but it **bypasses** the VM. You get inputs and outputs; you never see the obfuscation layer in between.
- **Route B (this write-up)**: **hard-reverse it** — read the interpreter, recover the instruction set, disassemble the bytecode, and reconstruct what it actually computes, instruction by instruction.

This document is about Route B, and about why some conclusions can *only* be reached that way. The tooling that came out of it is `vmrecover`.

## 1. Where the hash hides

In the signing chain there is a 16B → 32B transform (call it `X25`). Press F5 on it in IDA and the decompiler gives you one line:

```c
void sub_XXXX()
{
  JUMPOUT(0xXXXXLL);
}
```

`JUMPOUT` means the entry point is an OLLVM jump thunk; the real body is elsewhere. Dumping the real body reveals the classic three-stage hash skeleton:

```asm
BL  sub_XXXX   ; init
BL  sub_XXXX   ; update(input, 16)
BL  sub_XXXX   ; finalize -> 32 bytes out
```

But none of the three functions show any SHA/MD5 round operations — only `memcpy` and calls. Where's the algorithm? The answer is inside `init`:

```asm
ADRL X1, unk_XXXX          ; source table (encrypted on disk)
MOV  W2, #2                ; decrypt key = 2
MOV  W3, #0x1AF            ; length = 431 bytes
BL   decrypt_str           ; decrypt in place
...
BL   sub_XXXX              ; load bytecode
BL   sub_XXXX              ; interpreter executes!
```

The `decrypt + load + interpret` triad is the fingerprint: **this is a VM with self-decrypting bytecode**. `unk_XXXX` is the bytecode it consumes; `sub_XXXX` is the interpreter.

## 2. Why hard-reverse instead of unidbg

unidbg, used correctly, means: patch the environment, emulate, hook intermediate values, and assemble an offline reproduction script. It is very efficient — but be clear about what it **cannot** give you:

1. unidbg sees the VM's **inputs and outputs**, not its **instructions**. You know "input X → output Y"; you don't know the operations in between.
2. The moment the VM's output **doesn't match** any standard algorithm (true here, because of a post-processing layer), the black-box route stalls — you're left adding hooks and guesses.
3. Most importantly: obfuscated constants (like the SHA-256 IV split into two XOR halves) **exist only in instruction immediates**. Their complete form never exists in runtime memory. unidbg will never see `0x6a09e667`, because it only exists as the *result* of `push A; push B; xor`.

So hard-reversing isn't showing off — it's that **this layer's conclusions are only reachable by hard-reversing**. That's the core thesis: black-box tells you "it doesn't match"; only white-box tells you *why*.

## 3. Hard-reversing in four steps

### Step 1 — Confirm it's a VM

Export the interpreter's assembly. The very first glance is decisive — a textbook bytecode interpreter main loop:

```asm
LDRB W8, [X20]           ; fetch: read one byte from IP
CMP  W8, #0x54           ; switch, 85 cases
B.HI default             ; > 0x54 -> default
LDRH W10, [X26,X8,LSL#1] ; index the jump table
BR   X9                  ; dispatch
```

A `LDRB` fetch + an 85-entry jump table + a `BR` dispatch. `X20` is the instruction pointer, `X21` the stack pointer, `X23` the data base, `X22` a second register — a stack machine.

### Step 2 — Parse the bytecode table

Three bytecode tables (init/update/finalize), each with a fixed header of **six 32-bit fields**:

```
offset 0x00: magic     (identifies this table)
offset 0x04: lenA      main data segment length
offset 0x08: lenB      auxiliary data segment length
offset 0x0C: dataoff   (relocation placeholder base)
offset 0x10: nreloc    relocation entry count
offset 0x14: reserved  (always 0, purpose unknown)
offset 0x18: relocation table (8 bytes/entry, offsets into the data segment)
after:       bytecode segment (lenA + lenB bytes)
```

An easy trap: the header is **six** fields, not five — there's an always-zero word at `0x14`. Miss those 4 bytes and the entire relocation table is misaligned. `vmrecover.vmstruct.parse_table` handles exactly this.

The `init` table is encrypted on disk; `decrypt_str` is a position-dependent stream XOR:

```python
def decrypt_str(src, key):
    return bytes((b ^ ((key + 3 * i) & 0xff)) for i, b in enumerate(src))
```

key=2, step 3. The strength doesn't matter; the point is **defeating static scanning** — keeping `strings` and constant-scan from ever seeing plaintext bytecode.

### Step 3 — Write a disassembler, recover semantics

Read the semantics of all 85 interpreter cases and map them to instructions (`push_i32`, `ld_i8`, `xor32`, `brz`, `syscall`, `halt`, …). This is pure grunt work, but every cell must be pinned down from the assembly — no guessing. `vmrecover.disasm.Disassembler` consumes that table and emits structured instructions.

### Step 4 — Dig the hidden algorithm back out of the bytecode

Once disassembled, the real discoveries begin. Three things that black-box can never see, only read from bytecode:

**① The SHA-256 IV hidden behind "two-immediate XOR".**

At the start of the `init` bytecode, this pattern repeats:

```asm
push_i32 0x95f78fd1
push_i32 0xfffe69b6
xor32
```

Compute the XOR:

```
0x95f78fd1 ^ 0xfffe69b6 = 0x6a09e667
0x4499c730 ^ 0xfffe69b5 = 0xbb67ae85
...
```

`6a09e667 bb67ae85 3c6ef372 ...` — the eight standard SHA-256 IVs, every one. The VM splits each magic value into "encrypted value + decrementing key" so constant-scan can never find a naked `6a09e667`. `vmrecover.xorconst.fold_constants` automates this fold.

**② The relocation table that turns immediates into function pointers.**

In the update/finalize tables, several `push_i64` immediates are placeholders (`0x240`/`0x6c0`) that get replaced with real host addresses at load time. The VM doesn't hash by itself — it calls the host's compression function via `syscall`.

**③ Post-processing constants buried at the tail of `finalize`.**

The `finalize` table pushes two 32-byte constant tables byte-by-byte, then a loop:

```
out[i] = (sha256[i] + t1[i]) ^ t2[i]   (mod 256)
```

That's why `SHA256(m1)` never matched in black-box comparison — the VM wraps standard SHA-256 in "add t1, then XOR t2". The tables are buried in the bytecode, visible only to the disassembler.

## 4. Verification and conclusion

After recovering `X25 = POST(SHA256(m1))`, black-box verification used controlled differential testing: feed several 16-byte inputs, compare against our offline 32-byte outputs — **8/8 hit**.

Conclusion: this VM's job is not "implement hashing" but **orchestration + obfuscation** — calling the host's SHA-256 through `syscall`, then blinding both black-box and static analysis with three layers: two-immediate XOR for IVs, a relocation table for functions, and buried constants for post-processing.

## 5. Honest boundaries

- `vmrecover` does **not** auto-recover the instruction set. Opcode semantics are binary-specific and must be read by a human from the interpreter assembly; this tool provides the "semantic processing layer" you use *after* that reading.
- This tool does **not** emulate. It only disassembles and recognizes semantics. Dynamic verification (Frida differential testing, unidbg cross-check) is still the necessary final confirmation.
- All offsets, magic values, and constants here are illustrative; real values must be re-derived on an authorized sample.

## 6. Reusable pieces

| Module | Problem it solves |
|--------|-------------------|
| `vmrecover.disasm` | Given an opcode table, disassemble bytecode into structured instructions (with relocation annotations and jump targets) |
| `vmrecover.xorconst` | Detect `push A; push B; op` and fold out constants hidden behind two-immediate arithmetic |
| `vmrecover.vmstruct` | Parse the VM bytecode-table header (including that easily-missed sixth field) and relocation table |

> **A word for peers:** emulation lets you "run it", but the things hidden inside instruction immediates are only visible to the disassembler. The two aren't rivals — they're a sequence: use white-box to locate *why it doesn't match*, then black-box to confirm *whether your guess is right*.
