# vmrecover

**字节码 VM 的语义还原工具集——反汇编自定义 VM 的字节码，并折叠出它藏起来的常量。**

[English](README.md) | [中文](README.zh-CN.md)

加固后的 native 二进制里，一个常见的反分析套路是：把关键算法搬进一台自定义字节码 VM——真正的哈希/加密不再是普通函数，而是一段自解密字节码，由手写的解释器执行。黑盒手段（unidbg 模拟、运行时 hook）只能看到 VM 的输入输出，永远看不到藏在**指令立即数里**的混淆常量。

`vmrecover` 是"你读完解释器之后"的工具集：给定你手工还原出的 opcode 表，它把字节码反汇编成结构化指令、解析表头（含一个容易漏算的字段）、并折叠出被"双立即数运算"隐藏的常量。

## 为什么做这个

一个真实逆向项目里的两个发现，直接催生了本工具：

1. **藏在立即数里的常量，黑盒永远看不见。** SHA-256 的 IV 被拆成 `push A; push B; xor`（`0x95f78fd1 ^ 0xfffe69b6 == 0x6a09e667`）。完整值在运行期内存里根本不存在，任何 hook 或模拟器都观测不到——只有反汇编 + 常量折叠能拿到。
2. **一个 4 字节的表头字段，会悄悄毁掉一切。** 字节码表头是六个 32 位字段，不是五个；漏掉 `0x14` 处恒为 0 的那个字，后面整张重定位表全错位。

完整故事（含"硬刚 vs unidbg"的路线对比）见 [docs/case-study.zh-CN.md](docs/case-study.zh-CN.md)。

## 特性

- **`vmrecover.disasm`** — 把字节码反汇编成结构化 `Insn` 对象（偏移、opcode、助记符、指令长度、立即数、重定位标注、跳转目标）。
- **`vmrecover.xorconst`** — 识别 `push_imm A; push_imm B; <op>` 并折叠为 `A op B`，还原被双立即数运算隐藏的常量（支持 `xor`/`add`/`sub`，32/64 位）。
- **`vmrecover.vmstruct`** — 解析 VM 字节码表头（六个字段）及其重定位表。
- **CLI** — `parse`、`disasm`、`fold` 三个子命令。
- **零运行时依赖**；`pytest` 仅作为 test extra。

## 安装

```bash
git clone https://github.com/<user>/vmrecover.git
cd vmrecover
pip install -e .
```

## 快速开始

```bash
# 用 JSON opcode 表反汇编字节
vmrecover disasm --table examples/opcode_table.json --hex "07d18ff79507b669feff2350"

# 折叠被双立即数运算隐藏的常量
python examples/recover_sha256_iv.py
```

或作为库使用：

```python
from vmrecover.disasm import Disassembler
from vmrecover.xorconst import fold_constants

table = {0x07: ("push_i32", 4), 0x23: ("xor32", 0), 0x50: ("halt", 0)}
code = b"\x07" + (0x95F78FD1).to_bytes(4, "little") \
     + b"\x07" + (0xFFFE69B6).to_bytes(4, "little") \
     + b"\x23\x50"

insns = Disassembler(table).decode(code)
for hit in fold_constants(insns):
    print(f"{hit['a']:08x} ^ {hit['b']:08x} = {hit['value']:08x}")
# 95f78fd1 ^ fffe69b6 = 6a09e667
```

## 架构

```
字节码 blob ──> vmstruct.parse_table ──> Table（表头 + 重定位表 + 代码段）
                                              │
                                              v
opcode 表（JSON/py）──> disasm.Disassembler.decode ──> [Insn]
                                              │
                                              v
                              xorconst.fold_constants ──> 还原出的常量
```

```
vmrecover/
├── disasm.py     # Insn dataclass + Disassembler（decode/format）
├── xorconst.py   # fold_constants: push A; push B; op -> A op B
├── vmstruct.py   # Table + parse_table（六字段表头、重定位表）
└── cli.py        # parse / disasm / fold 子命令
```

## 诚实边界

- **它不会替你恢复指令集。** opcode 语义是二进制特定的，必须由人从解释器的分发 switch 里读出来；`vmrecover` 是你读完之后的处理层。
- **它不模拟执行。** 不跑字节码，只反汇编 + 语义识别。动态验证（Frida 差分测试、unidbg 对照）仍然是确认结论的必要一步。
- **只对应一种已知 VM 形态。** `vmstruct` 编码的是案例研究中那台 VM 的表头布局（六个 32 位字段、重定位表在 `0x18`）。别的 VM 布局不同；解析逻辑是参考实现，不是万能解析器。

## 文档

- [案例研究（中文）](docs/case-study.zh-CN.md) / [Case study (English)](docs/case-study.md) — 真实项目的脱敏复盘，含"硬刚 vs unidbg"的取舍，以及找到的三种藏常量手段。
- [examples/recover_sha256_iv.py](examples/recover_sha256_iv.py) — 端到端 demo：还原被双立即数 XOR 藏起来的 SHA-256 IV。
- [tools/ida_dump_asm.py](tools/ida_dump_asm.py) — 把 IDA 地址范围（如 VM 解释器的分发 switch）导出为反汇编文本。

## 开发

```bash
pip install -e ".[test]"
pytest
```

## 许可证

[MIT](LICENSE)
