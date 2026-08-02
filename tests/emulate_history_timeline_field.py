"""用 Unicorn 模拟 hexin 历史分时字段变长解码器 RVA 0x691d40，取 oracle。

背景见 docs/investigations/HISTORY_TIMELINE_OMISSION_STEP2_RE.md。`0x691d40` 是
`0x13dc220`/`0x13dc240` 的公共内层，逐字节 `shl ecx,7; or ecx,al` 把变长字段
组装成 4 字节值。本 harness：

- 把加载镜像整体 map 进 Unicorn；
- 准备一段记录字节作为输入（来自 tests/fixtures/history_timeline/）；
- 调 `0x691d40`（cdecl：输入指针、字段表指针、输出指针、首字节掩码），
  hook malloc/free/memcpy/memset；
- 读回输出，与 thsdk oracle 对照。

注意：`0x691d40` 内部调 `0x13e1db0`（同镜像代码，决定字段占几字节）。该内层
依赖对象状态，本 harness 先做**单字段探针**：直接喂已知 full 记录的某字段字节，
验证 `shl 7; or` 机制是否把裸字节还原成原值，作为机制坐实；low2 省略态的完整
恢复仍需配合同标的全字段 oracle。
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
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
)


FIELD_DECODER_RVA = 0x691D40
MALLOC_VA = 0x2332BA2
FREE_VA = 0x23310D9
MEMCPY_VA = 0x2321290
MEMSET_VA = 0x2321F10

PAGE_SIZE = 0x1000
INPUT_BASE = 0x50000000
OUTPUT_BASE = 0x51000000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x02000000
STACK_BASE = 0x70000000
STACK_SIZE = 0x00100000
RETURN_SENTINEL = 0x71000000


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & -alignment


def emulate_decode_field(image_bytes: bytes, field_bytes: bytes, first_mask: int) -> int:
    """调一次 0x691d40，返回它写出的 4 字节值。

    cdecl 参数：(input_ptr, field_table_ptr, output_ptr, first_byte_mask)。
    本探针把 field_table_ptr 也指向输入（内层 0x13e1db0 会用到，探针场景下
    尽量让它自洽）。
    """
    image = parse_image(image_bytes)
    image_base = image.image_base

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(image_base, align_up(image.image_size))
    uc.mem_write(image_base, image.data[: image.image_size])

    uc.mem_map(INPUT_BASE, max(PAGE_SIZE, align_up(len(field_bytes) + 32)))
    uc.mem_write(INPUT_BASE, field_bytes)
    uc.mem_map(OUTPUT_BASE, PAGE_SIZE)
    uc.mem_write(OUTPUT_BASE, b"\0" * 16)
    uc.mem_map(HEAP_BASE, HEAP_SIZE)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(RETURN_SENTINEL, PAGE_SIZE)

    heap_next = HEAP_BASE

    def return_from_call(return_value: int | None = None) -> None:
        esp = uc.reg_read(UC_X86_REG_ESP)
        return_address = struct.unpack("<I", uc.mem_read(esp, 4))[0]
        if return_value is not None:
            uc.reg_write(UC_X86_REG_EAX, return_value)
        uc.reg_write(UC_X86_REG_ESP, esp + 4)
        uc.reg_write(UC_X86_REG_EIP, return_address)

    def code_hook(_uc: Uc, address: int, _size: int, _user: object) -> None:
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

    stack_pointer = STACK_BASE + STACK_SIZE - 0x40
    uc.mem_write(
        stack_pointer,
        struct.pack(
            "<IIIII",
            RETURN_SENTINEL,   # return address
            INPUT_BASE,        # arg1: input ptr
            INPUT_BASE,        # arg2: field table ptr（探针：复用输入）
            OUTPUT_BASE,       # arg3: output ptr
            first_mask,        # arg4: 首字节掩码（0 读 / 0x40 跳过变体）
        ),
    )
    uc.reg_write(UC_X86_REG_ESP, stack_pointer)
    uc.reg_write(UC_X86_REG_EIP, image_base + FIELD_DECODER_RVA)
    uc.emu_start(
        image_base + FIELD_DECODER_RVA,
        RETURN_SENTINEL + 1,
        timeout=10_000_000,
        count=5_000_000,
    )
    return struct.unpack("<I", uc.mem_read(OUTPUT_BASE, 4))[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--image",
        type=Path,
        default=Path("captures_live/hexin.loaded.bin"),
    )
    ap.add_argument(
        "--record",
        type=Path,
        default=Path("tests/fixtures/history_timeline/000001_record_region.bin"),
        help="记录区 bin（由 build_history_timeline_fixtures.py 切出）",
    )
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=205, help="记录内偏移")
    ap.add_argument("--length", type=int, default=5, help="喂入字段字节数")
    ap.add_argument("--mask", type=lambda x: int(x, 0), default=0x40, help="首字节掩码")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    region = args.record.read_bytes()
    field_bytes = region[args.offset : args.offset + args.length]
    print(f"input field bytes (offset={args.offset}): {field_bytes.hex(' ')}")
    value = emulate_decode_field(args.image.read_bytes(), field_bytes, args.mask)
    print(f"decoded value = 0x{value:08x} = {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
