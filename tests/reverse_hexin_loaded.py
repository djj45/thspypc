"""针对 hexin.loaded.bin（UPX 解包后的内存 dump）的静态 RE 辅助工具。

该 dump 由 reverse_hexin_minidump.py extract-module 生成，关键性质是
**RVA == 文件偏移**；image_base 从加载映像 PE 头读取。因此标准的 pefile 节映射不适用，
本工具用 reverse_hlib_memory.parse_image 解析节，并在此前提下做：

- RTTI 类名 → CompleteObjectLocator → vtable → 构造函数引用；
- ASCII 字符串 → 绝对 32 位指针引用；
- 给定 RVA 的反汇编；
- 给定目标 RVA 的 call/jmp rel32 与指针引用。

背景见 docs/guides/THS_REVERSE_ENGINEERING_PLAYBOOK.md §5/§7，以及
docs/investigations/HISTORY_TIMELINE_OMISSION_STEP1_FINDINGS.md。
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reverse_hlib_memory import parse_image  # noqa: E402


def va(offset: int, image_base: int) -> int:
    """本 dump 中 RVA==文件偏移，故 VA = image_base + offset。"""
    return image_base + offset


def rva_from_va(value: int, image_base: int) -> int:
    return value - image_base


def find_all(data: bytes, needle: bytes) -> list[int]:
    matches: list[int] = []
    offset = 0
    while True:
        offset = data.find(needle, offset)
        if offset < 0:
            return matches
        matches.append(offset)
        offset += 1


def find_rtti(data: bytes, image_base: int, class_name: str) -> list[dict]:
    """返回某 MSVC 类的 vtable 信息。"""
    decorated_options = [
        f".?AV{class_name}@@".encode(),
        f".?AU{class_name}@@".encode(),
    ]
    name_offsets: list[int] = []
    for decorated in decorated_options:
        name_offsets.extend(find_all(data, decorated))
    results = []
    for name_offset in name_offsets:
        type_offset = name_offset - 8
        type_va = va(type_offset, image_base)
        entry = {
            "class": class_name,
            "decorated": data[name_offset : name_offset + len(decorated_options[0])].decode("ascii", "replace"),
            "type_descriptor_va": type_va,
            "vtables": [],
        }
        type_pointer = struct.pack("<I", type_va)
        for ref_offset in find_all(data, type_pointer):
            col_offset = ref_offset - 12
            if col_offset < 0:
                continue
            signature, _, _ = struct.unpack_from("<III", data, col_offset)
            if signature != 0:
                continue
            col_va = va(col_offset, image_base)
            col_pointer = struct.pack("<I", col_va)
            for slot_offset in find_all(data, col_pointer):
                vtable_offset = slot_offset + 4
                vtable_va = va(vtable_offset, image_base)
                methods = list(struct.unpack_from("<16I", data, vtable_offset))
                # 构造函数引用：vtable 指针的绝对地址出现在代码里
                vtable_pointer = struct.pack("<I", vtable_va)
                ctor_refs = [
                    va(o, image_base)
                    for o in find_all(data, vtable_pointer)
                    if o != vtable_offset
                ]
                entry["vtables"].append(
                    {
                        "col_va": col_va,
                        "vtable_va": vtable_va,
                        "vtable_rva": vtable_offset,
                        "methods": methods,
                        "ctor_refs": ctor_refs,
                    }
                )
        results.append(entry)
    return results


def find_string_refs(data: bytes, image_base: int, text: str) -> list[dict]:
    """找 ASCII 字符串及其绝对 32 位指针引用。"""
    needle = text.encode("utf-8")
    out = []
    for string_offset in find_all(data, needle):
        string_va = va(string_offset, image_base)
        refs = [
            va(o, image_base)
            for o in find_all(data, struct.pack("<I", string_va))
        ]
        out.append({"text": text, "string_rva": string_offset, "string_va": string_va, "refs_va": refs})
    return out


def find_code_refs(data: bytes, image_base: int, target_rva: int) -> list[dict]:
    """对目标 RVA 找 rel32 call/jmp 与绝对指针引用。"""
    target_va = va(target_rva, image_base)
    refs = []
    # 直接指针引用
    for o in find_all(data, struct.pack("<I", target_va)):
        refs.append({"kind": "pointer", "site_va": va(o, image_base)})
    # rel32 call/jmp：扫描 E8/E9
    for o in range(0, len(data) - 5):
        b = data[o]
        if b in (0xE8, 0xE9):
            disp = struct.unpack_from("<i", data, o + 1)[0]
            site_va = va(o, image_base)
            dest = site_va + 5 + disp
            if dest == target_va:
                refs.append({"kind": "call" if b == 0xE8 else "jmp", "site_va": site_va})
    refs.sort(key=lambda r: r["site_va"])
    return refs


def disasm(data: bytes, image_base: int, rva: int, size: int = 0x80) -> list[str]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "--disasm-rva requires the optional 'capstone' package"
        ) from exc
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = data[rva : rva + size]
    lines = []
    for ins in md.disasm(code, image_base + rva):
        lines.append(f"{ins.address - image_base:#x}: {ins.mnemonic} {ins.op_str}")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image", type=Path)
    ap.add_argument("--rtti", help="查 RTTI 类名")
    ap.add_argument("--string", help="查 ASCII 字符串引用")
    ap.add_argument("--xref-rva", action="append", type=lambda x: int(x, 0), help="查目标 RVA 的引用")
    ap.add_argument("--disasm-rva", action="append", type=lambda x: int(x, 0), help="反汇编目标 RVA")
    ap.add_argument("--disasm-size", type=lambda x: int(x, 0), default=0x80)
    args = ap.parse_args()

    data = args.image.read_bytes()
    img = parse_image(data)
    image_base = img.image_base
    print(f"image_base={image_base:#x} image_size={img.image_size:#x}")

    if args.rtti:
        for entry in find_rtti(data, image_base, args.rtti):
            print(f"RTTI {entry['class']} type_descriptor_va={entry['type_descriptor_va']:#x} decorated={entry['decorated']}")
            for vt in entry["vtables"]:
                methods_str = " ".join(hex(m) for m in vt["methods"][:8])
                print(f"  col={vt['col_va']:#x} vtable={vt['vtable_va']:#x} (rva={vt['vtable_rva']:#x})")
                print(f"    methods: {methods_str}")
                if vt["ctor_refs"]:
                    print(f"    ctor_refs: {[hex(r) for r in vt['ctor_refs']]}")

    if args.string:
        for entry in find_string_refs(data, image_base, args.string):
            print(f"string {entry['text']!r} rva={entry['string_rva']:#x} va={entry['string_va']:#x}")
            print(f"  refs: {[hex(r) for r in entry['refs_va']]}")

    if args.xref_rva:
        for target in args.xref_rva:
            refs = find_code_refs(data, image_base, target)
            print(f"xref target rva={target:#x} va={va(target, image_base):#x}: {len(refs)} refs")
            for r in refs[:20]:
                print(f"  {r['kind']:8s} site_va={r['site_va']:#x} (rva={r['site_va']-image_base:#x})")

    if args.disasm_rva:
        for rva in args.disasm_rva:
            print(f"=== disasm rva={rva:#x} ===")
            for line in disasm(data, image_base, rva, args.disasm_size):
                print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
