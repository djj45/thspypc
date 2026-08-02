"""用 Unicorn 模拟 hexin 历史分时整条解码链，读出省略字段恢复结果。

照搬 emulate_hexin_normalizer.py 的方法（playbook §8）：把加载镜像整体 map
进 Unicorn，hook malloc/free/memcpy/memset，调顶层解码函数，读回输出。

目标：让 `0x136b8e0`（吃记录区字节流、建字段表对象、调解码链）自然执行，
读出 low2 省略记录被控制字替换的 dt10 等字段的真实恢复值，从而确定 byte[1]
的恢复规则。

背景见 docs/investigations/HISTORY_TIMELINE_OMISSION_STEP2_RE.md。
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from reverse_hlib_memory import parse_image  # noqa: E402

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32, Uc  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_EAX,
    UC_X86_REG_EBP,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
)


# 顶层解码函数（cdecl：record_ptr, total_len, format_flag=0x10, output_obj_ptr）
DECODE_RVA = 0x136B8E0
MALLOC_VA = 0x2332BA2
FREE_VA = 0x23310D9
MEMCPY_VA = 0x2321290
MEMSET_VA = 0x2321F10

PAGE_SIZE = 0x1000
INPUT_BASE = 0x50000000
OUTPUT_BASE = 0x51000000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x04000000
STACK_BASE = 0x70000000
STACK_SIZE = 0x00100000
RETURN_SENTINEL = 0x71000000


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & -alignment


def emulate_decode(image_bytes: bytes, record_region: bytes) -> dict:
    """调 0x136b8e0，返回执行结果与诊断信息。"""
    image = parse_image(image_bytes)
    image_base = image.image_base

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(image_base, align_up(image.image_size))
    uc.mem_write(image_base, image.data[: image.image_size])

    uc.mem_map(INPUT_BASE, max(PAGE_SIZE, align_up(len(record_region) + 64)))
    uc.mem_write(INPUT_BASE, record_region)
    uc.mem_map(OUTPUT_BASE, PAGE_SIZE)
    uc.mem_write(OUTPUT_BASE, b"\0" * 64)
    uc.mem_map(HEAP_BASE, HEAP_SIZE)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(RETURN_SENTINEL, PAGE_SIZE)

    heap_next = HEAP_BASE
    diag = {"calls": [], "errors": []}

    def return_from_call(return_value: int | None = None) -> None:
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack("<I", uc.mem_read(esp, 4))[0]
        if return_value is not None:
            uc.reg_write(UC_X86_REG_EAX, return_value)
        uc.reg_write(UC_X86_REG_ESP, esp + 4)
        uc.reg_write(UC_X86_REG_EIP, ret_addr)

    def code_hook(_uc, address, _size, _ud):
        nonlocal heap_next
        esp = uc.reg_read(UC_X86_REG_ESP)
        if address == MALLOC_VA:
            size = struct.unpack("<I", _uc.mem_read(esp + 4, 4))[0]
            size = max(1, align_up(size, 16))
            allocation = heap_next
            heap_next += size
            if heap_next > HEAP_BASE + HEAP_SIZE:
                raise MemoryError("emulated heap exhausted")
            return_from_call(allocation)
        elif address == FREE_VA:
            return_from_call()
        elif address == MEMCPY_VA:
            dst, src, count = struct.unpack("<III", _uc.mem_read(esp + 4, 12))
            _uc.mem_write(dst, bytes(_uc.mem_read(src, count)))
            return_from_call(dst)
        elif address == MEMSET_VA:
            dst, val, count = struct.unpack("<III", _uc.mem_read(esp + 4, 12))
            _uc.mem_write(dst, bytes([val & 0xFF]) * count)
            return_from_call(dst)
        elif address == RETURN_SENTINEL:
            _uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, code_hook)

    # cdecl 栈帧：[ret_addr, arg1, arg2, arg3, arg4]
    sp = STACK_BASE + STACK_SIZE - 0x40
    uc.mem_write(
        sp,
        struct.pack(
            "<IIIII",
            RETURN_SENTINEL,   # return address
            INPUT_BASE,        # arg1: record region ptr
            len(record_region),# arg2: total length
            0x10,              # arg3: format flag
            OUTPUT_BASE,       # arg4: output object ptr
        ),
    )
    uc.reg_write(UC_X86_REG_ESP, sp)
    uc.reg_write(UC_X86_REG_EIP, image_base + DECODE_RVA)

    try:
        uc.emu_start(
            image_base + DECODE_RVA,
            RETURN_SENTINEL + 1,
            timeout=30_000_000,
            count=20_000_000,
        )
    except Exception as exc:
        diag["errors"].append(f"emu error: {exc}")
        diag["errors"].append(f"EIP=0x{uc.reg_read(UC_X86_REG_EIP):#x}")

    eax = uc.reg_read(UC_X86_REG_EAX)
    diag["eax"] = eax
    diag["output_ptr"] = struct.unpack("<I", uc.mem_read(OUTPUT_BASE, 4))[0]
    diag["heap_used"] = heap_next - HEAP_BASE
    # 读 output 对象区域
    diag["output_bytes"] = bytes(uc.mem_read(OUTPUT_BASE, 64)).hex(" ")
    return diag


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", type=Path, default=Path("captures_live/hexin.loaded.bin"))
    ap.add_argument(
        "--record",
        type=Path,
        default=Path("tests/fixtures/history_timeline/000001_record_region.bin"),
    )
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # 喂入完整记录区（字段表 + 壳 + 记录数据）
    region = args.record.read_bytes()
    print(f"record region: {len(region)}B")
    print(f"first 16B: {region[:16].hex(' ')}")

    diag = emulate_decode(args.image.read_bytes(), region)
    print(f"eax (return): 0x{diag['eax']:#x}")
    print(f"output_ptr: 0x{diag['output_ptr']:#x}")
    print(f"heap_used: {diag['heap_used']}B")
    print(f"output_bytes: {diag['output_bytes']}")
    for err in diag["errors"]:
        print(f"ERROR: {err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
