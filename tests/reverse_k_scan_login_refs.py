"""阶段 1a：扫描引用 login 字段串池的指令，定位 login-body 构造函数。

背景见 docs/handoffs/HANDOFF_LOGIN_PROTOCOL_20260810.md 的 K 值来源调查。
阶段 0 发现 handoff 的地址表有 0x70000 系统偏差，且 login 字段字符串池
（thsuser/__manual/zh_CN.GBK/Password/VerifyType/Mac64/C-Support*/VerifyCode）
整齐排列在 VA 0x24d911c~0x24d91b0，但零绝对指针引用。

本脚本用 Capstone 线性扫描所有可执行段，找任何 imm / [disp] 落在该池的指令，
从而定位 login-body 构造函数。这是 playbook §5.4「定向反汇编」的实践。

⚠ 诊断脚本（playbook §13），只输出引用点，不做解码。
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reverse_hlib_memory import parse_image  # noqa: E402

# DMP 镜像的运行时加载基址（PE 头 ImageBase=0x650000 是错的，实测指针按 0xa50000 编码）
RUNTIME_BASE = 0xA50000
# login 字段串池范围（阶段 0 实测）
POOL_LO = 0x24D911C  # thsuser
POOL_HI = 0x24D91B4  # VerifyCode 之后


def main() -> int:
    image_path = Path(sys.argv[1] if len(sys.argv) > 1 else "captures_live/hexin.dmp.loaded.bin")
    data = image_path.read_bytes()
    img = parse_image(data)
    print(f"image_base(PE头)={img.image_base:#x} runtime_base={RUNTIME_BASE:#x} size={img.image_size:#x}")
    print(f"login 字段池: VA [{POOL_LO:#x}, {POOL_HI:#x})")
    print(f"可执行段:")
    for s in img.sections:
        if s.executable:
            print(f"  {s.name}: VA [{s.virtual_address:#x}, {s.virtual_address+s.virtual_size:#x})")

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    except ModuleNotFoundError:
        print("需要 capstone: py -m pip install capstone", file=sys.stderr)
        return 1

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True

    refs: list[tuple[int, str, str, str, str]] = []  # (rva, field, bytes, mnemonic, op_str)
    total_ins = 0
    for s in img.sections:
        if not s.executable or s.virtual_size == 0:
            continue
        start = s.virtual_address
        end = min(start + s.virtual_size, len(data))
        for ins in md.disasm(data[start:end], RUNTIME_BASE + start):
            total_ins += 1
            if ins.id == 0:  # skipdata 伪指令，无 operands
                continue
            try:
                operands = ins.operands
            except Exception:
                continue
            for op in operands:
                val = None
                if op.type == X86_OP_IMM:
                    val = op.imm
                elif op.type == X86_OP_MEM:
                    val = op.mem.disp
                if val is not None and POOL_LO <= val < POOL_HI:
                    # 解出指向哪个字段
                    field_off = val - RUNTIME_BASE
                    field_bytes = data[field_off:field_off + 24].split(b"\x00")[0]
                    try:
                        field_name = field_bytes.decode("ascii")
                    except UnicodeDecodeError:
                        field_name = field_bytes.hex()
                    refs.append((
                        ins.address - RUNTIME_BASE,
                        f"{field_name}@{val:#x}",
                        ins.bytes.hex(" "),
                        ins.mnemonic,
                        ins.op_str,
                    ))
                    break

    print(f"\n扫描完成：{total_ins:,} 条指令，{len(refs)} 处引用 login 字段池")
    print(f"\n=== 引用点（按字段分组）===")
    by_field: dict[str, list] = {}
    for r in refs:
        by_field.setdefault(r[1], []).append(r)
    for field in sorted(by_field):
        print(f"\n  {field} ({len(by_field[field])} 处):")
        for rva, field, hexb, mnem, ops in by_field[field][:12]:
            print(f"    RVA {rva:#010x}  {hexb:20s}  {mnem} {ops}")

    # 重点：找引用多个不同 login 字段的"密集函数"——那大概率是 login-body 构造函数
    print(f"\n=== 引用 ≥3 个不同 login 字段的函数区间（密集引用 → login 构造函数候选）===")
    # 把引用按 RVA 聚类（相邻 0x1000 内视为同函数）
    if refs:
        refs_sorted = sorted(refs, key=lambda r: r[0])
        clusters: list[list] = []
        for r in refs_sorted:
            if clusters and r[0] - clusters[-1][-1][0] < 0x1000:
                clusters[-1].append(r)
            else:
                clusters.append([r])
        for c in clusters:
            fields_seen = {r[1].split("@")[0] for r in c}
            if len(fields_seen) >= 3:
                print(f"\n  簇 RVA [{c[0][0]:#x}, {c[-1][0]:#x}] ({len(c)} 处引用, {len(fields_seen)} 个不同字段):")
                for field in sorted(fields_seen):
                    print(f"    - {field}")
                print(f"    首条指令: {c[0][3]} {c[0][4]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
