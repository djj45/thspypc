#!/usr/bin/env python
"""Trace hexin's CHQuoteFile::parse on a real normalized 4417 buffer.

Goal: locate the record decoder that handles the flag=0x0082 stock tables
("strong-state omission" codec).  We construct a minimal CHQuoteFile object
(vtable at 0x1acb2bc), call parse(this, buffer, length, mode=0), and log
every call plus every memory access into the record regions.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from reverse_hlib_memory import parse_image  # noqa: E402

from unicorn import (  # noqa: E402
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_UNMAPPED,
    UC_MODE_32,
    Uc,
)
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_EAX,
    UC_X86_REG_EBP,
    UC_X86_REG_ECX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
)


PARSE_RVA = 0x127C8B0
CTOR_RVA = 0x127C570
CHQUOTE_VTABLE_RVA = 0x1ACB2BC
MALLOC_VA = 0x650000 + 0x15E2BA2
FREE_VA = 0x650000 + 0x15E10D9
MEMCPY_VA = 0x650000 + 0x15D1290

PAGE_SIZE = 0x1000
OBJECT_BASE = 0x50000000
BUFFER_BASE = 0x51000000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x10000000
STACK_BASE = 0x70000000
STACK_SIZE = 0x01000000
RETURN_SENTINEL = 0x71000000


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & -alignment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("normalized", type=Path)
    parser.add_argument(
        "--image",
        type=Path,
        default=Path("captures_live/hexin.dmp.loaded.bin"),
    )
    parser.add_argument("--max-calls", type=int, default=200000)
    parser.add_argument("--trace-calls", action="store_true")
    parser.add_argument(
        "--table-offset", type=lambda value: int(value, 0), default=0
    )
    parser.add_argument("--executed-out", type=Path)
    parser.add_argument("--heap-dump", type=Path)
    args = parser.parse_args()

    normalized = args.normalized.read_bytes()
    if args.table_offset:
        normalized = normalized[args.table_offset :]
    image = parse_image(args.image.read_bytes())
    print(
        f"image_base=0x{image.image_base:08x} image_size=0x{image.image_size:x} "
        f"buffer={len(normalized)} bytes"
    )

    emulator = Uc(UC_ARCH_X86, UC_MODE_32)
    emulator.mem_map(image.image_base, align_up(image.image_size))
    emulator.mem_write(image.image_base, image.data[: image.image_size])
    emulator.mem_map(OBJECT_BASE, align_up(0x2000))
    emulator.mem_map(BUFFER_BASE, align_up(len(normalized) + 0x1000))
    emulator.mem_write(BUFFER_BASE, normalized)
    emulator.mem_map(HEAP_BASE, HEAP_SIZE)
    emulator.mem_map(STACK_BASE, STACK_SIZE)
    emulator.mem_map(RETURN_SENTINEL, PAGE_SIZE)
    # SEH prologues read/write fs:[0]; Unicorn's FS base defaults to 0.
    emulator.mem_map(0, PAGE_SIZE)
    emulator.mem_write(0, b"\0" * PAGE_SIZE)

    heap_next = HEAP_BASE
    call_log: list[tuple[int, int]] = []
    record_touches: list[tuple[int, int, int]] = []  # (pc, address, size)
    executed: list[int] = []
    executed_set: set[int] = set()

    # record regions: first 0x0082 table header at 0x8d -> records at 0xf9;
    # second at 0x5821 -> records at 0x588d.  Track whole tables for now.
    offset = args.table_offset
    record_ranges = [
        (0x8D - offset, 0x5821 - offset),
        (0x5821 - offset, 0xAFB5 - offset),
    ]

    def return_from_call(return_value: int | None = None) -> None:
        esp = emulator.reg_read(UC_X86_REG_ESP)
        return_address = struct.unpack("<I", emulator.mem_read(esp, 4))[0]
        if return_value is not None:
            emulator.reg_write(UC_X86_REG_EAX, return_value)
        emulator.reg_write(UC_X86_REG_ESP, esp + 4)
        emulator.reg_write(UC_X86_REG_EIP, return_address)

    def code_hook(_uc, address, _size, _user):
        nonlocal heap_next
        if address == MALLOC_VA:
            esp = emulator.reg_read(UC_X86_REG_ESP)
            allocation_size = struct.unpack("<I", emulator.mem_read(esp + 4, 4))[0]
            allocation_size = max(1, align_up(allocation_size, 16))
            allocation = heap_next
            heap_next += allocation_size
            if heap_next > HEAP_BASE + HEAP_SIZE:
                raise MemoryError("emulated heap exhausted")
            return_from_call(allocation)
        elif address == FREE_VA:
            return_from_call()
        elif address == MEMCPY_VA:
            esp = emulator.reg_read(UC_X86_REG_ESP)
            destination, source, count = struct.unpack(
                "<III", emulator.mem_read(esp + 4, 12)
            )
            emulator.mem_write(
                destination, bytes(emulator.mem_read(source, count))
            )
            return_from_call(destination)
        elif address == RETURN_SENTINEL:
            emulator.emu_stop()
        rva = address - image.image_base
        if rva not in executed_set:
            executed_set.add(rva)
            executed.append(rva)
        if args.trace_calls and len(executed_set) >= args.max_calls:
            emulator.emu_stop()

    def mem_hook_factory(kind: str):
        def hook(_uc, access, address, size, value, _user):
            pc = emulator.reg_read(UC_X86_REG_EIP)
            rva = pc - image.image_base
            for start, end in record_ranges:
                if BUFFER_BASE + start <= address < BUFFER_BASE + end:
                    record_touches.append(
                        (rva, address - BUFFER_BASE, size)
                    )
                    break

        return hook

    def unmapped_hook(_uc, access, address, size, value, _user):
        pc = emulator.reg_read(UC_X86_REG_EIP)
        print(
            f"unmapped access={access} addr=0x{address:08x} size={size} "
            f"pc=0x{pc - image.image_base:08x}"
        )
        return False

    emulator.hook_add(UC_HOOK_CODE, code_hook)
    emulator.hook_add(UC_HOOK_MEM_READ, mem_hook_factory("read"))
    emulator.hook_add(UC_HOOK_MEM_WRITE, mem_hook_factory("write"))
    emulator.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped_hook)

    # 1) run the real constructor on the object
    stack_pointer = STACK_BASE + STACK_SIZE - 0x40
    emulator.mem_write(
        stack_pointer, struct.pack("<I", RETURN_SENTINEL)
    )
    emulator.reg_write(UC_X86_REG_ESP, stack_pointer)
    emulator.reg_write(UC_X86_REG_ECX, OBJECT_BASE)
    emulator.reg_write(UC_X86_REG_EIP, image.image_base + CTOR_RVA)
    emulator.emu_start(
        image.image_base + CTOR_RVA,
        RETURN_SENTINEL,
        timeout=60_000_000,
        count=50_000_000,
    )
    print(
        "ctor done, vtable="
        f"0x{struct.unpack('<I', emulator.mem_read(OBJECT_BASE, 4))[0]:08x}"
    )

    # 2) call parse(this, buffer, length, mode=0)
    emulator.mem_write(
        stack_pointer,
        struct.pack(
            "<IIII", RETURN_SENTINEL, BUFFER_BASE, len(normalized), 0
        ),
    )
    emulator.reg_write(UC_X86_REG_ESP, stack_pointer)
    emulator.reg_write(UC_X86_REG_ECX, OBJECT_BASE)
    emulator.reg_write(UC_X86_REG_EIP, image.image_base + PARSE_RVA)
    try:
        emulator.emu_start(
            image.image_base + PARSE_RVA,
            RETURN_SENTINEL,
            timeout=120_000_000,
            count=200_000_000,
        )
    except Exception as exc:  # noqa: BLE001
        eip = emulator.reg_read(UC_X86_REG_EIP)
        print(f"emu stopped: {exc} eip=0x{eip - image.image_base:08x}")

    eip = emulator.reg_read(UC_X86_REG_EIP)
    eax = emulator.reg_read(UC_X86_REG_EAX)
    print(
        f"final eip=0x{eip - image.image_base:08x} "
        f"eax=0x{eax:08x} object=[0]=0x"
        f"{struct.unpack('<I', emulator.mem_read(OBJECT_BASE, 4))[0]:08x}"
    )
    obj = bytes(emulator.mem_read(OBJECT_BASE, 0x2000))
    heap_region = bytes(emulator.mem_read(HEAP_BASE, min(0x200000, heap_next - HEAP_BASE)))
    for needle, label in [
        (struct.pack("<I", 132477534), "bar 132477534"),
        (b"000938", "code 000938"),
        (b"hd1.0", "hd1.0"),
    ]:
        for region_name, region in (("object", obj), ("heap", heap_region)):
            offsets = []
            start = 0
            while True:
                p = region.find(needle, start)
                if p < 0:
                    break
                offsets.append(hex(p))
                start = p + 1
            if offsets:
                print(f"{region_name} contains {label}: {offsets[:10]}")
    print(f"heap used: 0x{heap_next - HEAP_BASE:x}")
    if args.heap_dump:
        args.heap_dump.write_bytes(heap_region)
        print(f"wrote heap dump to {args.heap_dump}")
    print(f"record touches: {len(record_touches)}")
    if args.executed_out:
        with args.executed_out.open("w") as f:
            for rva in executed:
                f.write(f"{rva:08x}\n")
        print(f"wrote executed list to {args.executed_out}")
    # summarize touches per pc
    from collections import Counter

    pc_counts = Counter(rva for rva, _addr, _size in record_touches)
    for rva, count in pc_counts.most_common(30):
        print(f"  touch pc=0x{rva:08x} count={count}")
    if args.trace_calls:
        print(f"calls logged: {len(call_log)}")
        print(f"distinct executed instructions: {len(executed_set)}")
        print("first 250 executed (rva):")
        for rva in executed[:250]:
            print(f"  0x{rva:08x}")
        print("last 120 executed (rva):")
        for rva in executed[-120:]:
            print(f"  0x{rva:08x}")
        # cluster into function footprints
        footprint: list[tuple[int, int]] = []
        for rva in sorted(executed_set):
            if footprint and rva - footprint[-1][1] <= 0x200:
                footprint[-1][1] = rva
            else:
                footprint.append([rva, rva])
        print("executed footprints:")
        for lo, hi in footprint:
            print(f"  0x{lo:08x}-0x{hi:08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
