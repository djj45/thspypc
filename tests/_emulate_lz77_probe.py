#!/usr/bin/env python
"""Emulate hexin's outer 8901 decompressor (RVA 0xf74260) from a DMP image.

The loaded image is extracted from a Task Manager minidump with
``tests/reverse_hexin_minidump.py extract-module``; on-disk hexin.exe is
UPX-packed and the runtime layout (UPX0/UPX1 sections) differs from
``upx -d`` output, so only the DMP-derived image is a faithful oracle.

This build's normalizer is self-contained apart from three static CRT
helpers (malloc/free/memcpy), which are emulated with a bump allocator.
The output is compared byte-for-byte against the Python port
(``normalize_8901_response``); a mismatch pinpoints porting bugs (the
historical timeline frames exposed a long-match off-by-one).

Usage:
    py tests/_emulate_lz77_probe.py captures_live/xxx.bin \
        --image captures_live/hexin.dmp.loaded.bin \
        [--writes-out writes.txt]
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
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MODE_32,
    Uc,
)
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_EAX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
)


NORMALIZER_RVA = 0xF74260  # valid in the DMP runtime image
# static CRT helpers in the DMP runtime image (absolute VAs, base 0x650000):
MALLOC_VA = 0x650000 + 0x15E2BA2
FREE_VA = 0x650000 + 0x15E10D9
MEMCPY_VA = 0x650000 + 0x15D1290

PAGE_SIZE = 0x1000
INPUT_BASE = 0x50000000
OUTPUT_SLOT = 0x51000000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x10000000
STACK_BASE = 0x70000000
STACK_SIZE = 0x01000000
RETURN_SENTINEL = 0x71000000
MAX_OUTPUT_SIZE = 0x01000000


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & -alignment


def emulate_normalizer(
    image_path: Path,
    raw: bytes,
    writes_out: Path | None = None,
    input_reads_out: Path | None = None,
) -> bytes:
    image = parse_image(image_path.read_bytes())
    compressed = raw[1:] if raw[:1] == b"\x0a" else raw
    if len(compressed) < 5:
        raise ValueError("compressed payload is too short")
    expected_size = struct.unpack_from(">I", compressed)[0]
    if not 0 < expected_size <= MAX_OUTPUT_SIZE:
        raise ValueError(f"invalid BE32 output size 0x{expected_size:x}")

    emulator = Uc(UC_ARCH_X86, UC_MODE_32)
    emulator.mem_map(image.image_base, align_up(image.image_size))
    emulator.mem_write(image.image_base, image.data[: image.image_size])
    # SEH prologues read/write fs:[0]; Unicorn's FS base defaults to 0.
    emulator.mem_map(0, PAGE_SIZE)
    emulator.mem_write(0, b"\0" * PAGE_SIZE)
    emulator.mem_map(INPUT_BASE, align_up(len(compressed)))
    emulator.mem_write(INPUT_BASE, compressed)
    emulator.mem_map(OUTPUT_SLOT, PAGE_SIZE)
    emulator.mem_write(OUTPUT_SLOT, b"\0\0\0\0")
    emulator.mem_map(HEAP_BASE, HEAP_SIZE)
    emulator.mem_map(STACK_BASE, STACK_SIZE)
    emulator.mem_map(RETURN_SENTINEL, PAGE_SIZE)

    heap_next = HEAP_BASE
    input_copy_base: int | None = None
    input_copy_size = 0
    heap_writes: list[tuple[int, int, int]] = []
    input_reads: list[tuple[int, int]] = []

    def return_from_call(return_value: int | None = None) -> None:
        esp = emulator.reg_read(UC_X86_REG_ESP)
        return_address = struct.unpack("<I", emulator.mem_read(esp, 4))[0]
        if return_value is not None:
            emulator.reg_write(UC_X86_REG_EAX, return_value)
        emulator.reg_write(UC_X86_REG_ESP, esp + 4)
        emulator.reg_write(UC_X86_REG_EIP, return_address)

    def code_hook(_uc, address, _size, _user):
        nonlocal heap_next, input_copy_base, input_copy_size
        esp = emulator.reg_read(UC_X86_REG_ESP)
        if address == MALLOC_VA:
            allocation_size = struct.unpack(
                "<I", emulator.mem_read(esp + 4, 4)
            )[0]
            allocation_size = max(1, align_up(allocation_size, 16))
            allocation = heap_next
            heap_next += allocation_size
            if heap_next > HEAP_BASE + HEAP_SIZE:
                raise MemoryError("emulated heap exhausted")
            return_from_call(allocation)
        elif address == FREE_VA:
            return_from_call()
        elif address == MEMCPY_VA:
            destination, source, count = struct.unpack(
                "<III", emulator.mem_read(esp + 4, 12)
            )
            if 0x1000 < count < 0x100000:
                input_copy_base = destination
                input_copy_size = count
            emulator.mem_write(
                destination, bytes(emulator.mem_read(source, count))
            )
            return_from_call(destination)
        elif address == RETURN_SENTINEL:
            emulator.emu_stop()

    def write_hook(*hook_args):
        _uc, _access, address, _size, value, _user = hook_args
        if HEAP_BASE <= address < HEAP_BASE + HEAP_SIZE:
            heap_writes.append(
                (emulator.reg_read(UC_X86_REG_EIP) - image.image_base, address, value)
            )

    def read_hook(*hook_args):
        _uc, _access, address, _size, _value, _user = hook_args
        if input_copy_base is not None:
            if input_copy_base <= address < input_copy_base + input_copy_size:
                input_reads.append(
                    (
                        emulator.reg_read(UC_X86_REG_EIP) - image.image_base,
                        address - input_copy_base,
                    )
                )

    def unmapped_hook(_uc, access, address, size, _value, _user):
        pc = emulator.reg_read(UC_X86_REG_EIP)
        print(
            f"unmapped access={access} addr=0x{address:08x} size={size} "
            f"pc=0x{pc - image.image_base:08x}"
        )
        return False

    emulator.hook_add(UC_HOOK_CODE, code_hook)
    emulator.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    emulator.hook_add(UC_HOOK_MEM_READ, read_hook)
    emulator.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped_hook)

    stack_pointer = STACK_BASE + STACK_SIZE - 0x20
    emulator.mem_write(
        stack_pointer,
        struct.pack(
            "<IIII", RETURN_SENTINEL, INPUT_BASE, len(compressed), OUTPUT_SLOT
        ),
    )
    emulator.reg_write(UC_X86_REG_ESP, stack_pointer)
    emulator.reg_write(UC_X86_REG_EIP, image.image_base + NORMALIZER_RVA)
    emulator.emu_start(
        image.image_base + NORMALIZER_RVA,
        RETURN_SENTINEL,
        timeout=60_000_000,
        count=500_000_000,
    )

    actual_size = emulator.reg_read(UC_X86_REG_EAX)
    output_address = struct.unpack(
        "<I", emulator.mem_read(OUTPUT_SLOT, 4)
    )[0]
    print(
        f"returned eax=0x{actual_size:x} output_ptr=0x{output_address:08x} "
        f"expected=0x{expected_size:x}"
    )
    if not HEAP_BASE <= output_address < HEAP_BASE + HEAP_SIZE:
        raise RuntimeError(f"invalid output pointer 0x{output_address:x}")

    if writes_out is not None:
        with writes_out.open("w") as f:
            for pc, addr, val in heap_writes:
                off = addr - HEAP_BASE
                if 0 <= off < 0x10000:
                    f.write(f"{off:04x} {val:02x} {pc:08x}\n")
        print(f"wrote heap-write trace to {writes_out}")
    if input_reads_out is not None:
        with input_reads_out.open("w") as f:
            for pc, off in input_reads:
                f.write(f"{off:04x} {pc:08x}\n")
        print(f"wrote input-read trace to {input_reads_out}")
    if input_copy_base is not None:
        print(
            f"input copy base=0x{input_copy_base:08x} "
            f"size=0x{input_copy_size:x} reads={len(input_reads)}"
        )

    return bytes(emulator.mem_read(output_address, actual_size))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--image",
        type=Path,
        default=Path("captures_live/hexin.dmp.loaded.bin"),
    )
    parser.add_argument("--writes-out", type=Path)
    parser.add_argument("--input-reads-out", type=Path)
    args = parser.parse_args()

    raw = args.input.read_bytes()
    normalized = emulate_normalizer(
        args.image,
        raw,
        writes_out=args.writes_out,
        input_reads_out=args.input_reads_out,
    )
    print(f"input={args.input} raw_size={len(raw)} normalized_size={len(normalized)}")
    print(f"head={normalized[:64].hex(' ')}")

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from thspypc.codecs.compression import normalize_8901_response

    python_normalized = normalize_8901_response(raw)
    print(f"python normalize size={len(python_normalized)}")
    if python_normalized == normalized:
        print(
            "MATCH: native emulation == python normalize_8901_response "
            "(byte-for-byte)"
        )
    else:
        common = 0
        for a, b in zip(python_normalized, normalized):
            if a != b:
                break
            common += 1
        print(
            f"MISMATCH: first difference at byte {common} "
            f"(native {normalized[common:common+16].hex(' ')!r}, "
            f"python {python_normalized[common:common+16].hex(' ')!r})"
        )
        if python_normalized[: len(normalized)] == normalized:
            tail = python_normalized[len(normalized) :]
            zero_filled = tail == b"\0" * len(tail)
            print(
                f"native output is a PREFIX of python output; "
                f"python tail={len(tail)} bytes, zero-filled={zero_filled}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
