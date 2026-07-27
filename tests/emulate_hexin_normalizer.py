#!/usr/bin/env python
"""Emulate hexin's outer 8901 response decompressor from a loaded image.

The 8901 frame body begins with command byte 0x0a.  Hexin removes that byte
and passes the remainder to RVA 0xf74260:

    BE32 uncompressed_size
    compressed bytes

The function is pure x86 apart from malloc/free/memcpy, so Unicorn can execute
it without launching or modifying the installed client.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

from reverse_hlib_memory import parse_image


NORMALIZER_RVA = 0xF74260
MALLOC_VA = 0x2332BA2
FREE_VA = 0x23310D9
MEMCPY_VA = 0x2321290

PAGE_SIZE = 0x1000
INPUT_BASE = 0x50000000
OUTPUT_SLOT = 0x51000000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x02000000
STACK_BASE = 0x70000000
STACK_SIZE = 0x00100000
RETURN_SENTINEL = 0x71000000
MAX_OUTPUT_SIZE = 0x01000000


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & -alignment


def emulate_normalizer(image_path: Path, raw: bytes) -> bytes:
    image = parse_image(image_path.read_bytes())
    compressed = raw[1:] if raw[:1] == b"\x0a" else raw
    if len(compressed) < 5:
        raise ValueError("compressed payload is too short")
    expected_size = struct.unpack_from(">I", compressed)[0]
    if not 0 < expected_size <= MAX_OUTPUT_SIZE:
        raise ValueError(
            f"invalid BE32 output size 0x{expected_size:x}; "
            "the input may still include a transport command byte"
        )

    emulator = Uc(UC_ARCH_X86, UC_MODE_32)
    image_map_size = align_up(image.image_size)
    emulator.mem_map(image.image_base, image_map_size)
    emulator.mem_write(image.image_base, image.data[:image.image_size])

    input_map_size = align_up(len(compressed))
    emulator.mem_map(INPUT_BASE, input_map_size)
    emulator.mem_write(INPUT_BASE, compressed)
    emulator.mem_map(OUTPUT_SLOT, PAGE_SIZE)
    emulator.mem_write(OUTPUT_SLOT, b"\0\0\0\0")
    emulator.mem_map(HEAP_BASE, HEAP_SIZE)
    emulator.mem_map(STACK_BASE, STACK_SIZE)
    emulator.mem_map(RETURN_SENTINEL, PAGE_SIZE)

    heap_next = HEAP_BASE

    def return_from_call(return_value: int | None = None) -> None:
        esp = emulator.reg_read(UC_X86_REG_ESP)
        return_address = struct.unpack(
            "<I", emulator.mem_read(esp, 4)
        )[0]
        if return_value is not None:
            emulator.reg_write(UC_X86_REG_EAX, return_value)
        emulator.reg_write(UC_X86_REG_ESP, esp + 4)
        emulator.reg_write(UC_X86_REG_EIP, return_address)

    def code_hook(_uc: Uc, address: int, _size: int, _user_data: object) -> None:
        nonlocal heap_next
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
            emulator.mem_write(destination, bytes(emulator.mem_read(source, count)))
            return_from_call(destination)
        elif address == RETURN_SENTINEL:
            emulator.emu_stop()

    emulator.hook_add(UC_HOOK_CODE, code_hook)

    stack_pointer = STACK_BASE + STACK_SIZE - 0x20
    emulator.mem_write(
        stack_pointer,
        struct.pack(
            "<IIII",
            RETURN_SENTINEL,
            INPUT_BASE,
            len(compressed),
            OUTPUT_SLOT,
        ),
    )
    emulator.reg_write(UC_X86_REG_ESP, stack_pointer)
    emulator.reg_write(UC_X86_REG_EIP, image.image_base + NORMALIZER_RVA)
    emulator.emu_start(
        image.image_base + NORMALIZER_RVA,
        RETURN_SENTINEL + 1,
        timeout=15_000_000,
        count=100_000_000,
    )

    actual_size = emulator.reg_read(UC_X86_REG_EAX)
    output_address = struct.unpack(
        "<I", emulator.mem_read(OUTPUT_SLOT, 4)
    )[0]
    if actual_size != expected_size:
        raise RuntimeError(
            f"normalizer returned {actual_size}, expected {expected_size}"
        )
    if not HEAP_BASE <= output_address < HEAP_BASE + HEAP_SIZE:
        raise RuntimeError(f"invalid emulated output pointer 0x{output_address:x}")
    return bytes(emulator.mem_read(output_address, actual_size))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="8901 frame body or compressed payload")
    parser.add_argument(
        "--image",
        type=Path,
        default=Path("captures_live/hexin.loaded.bin"),
        help="loaded hexin image reconstructed from the minidump",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    raw = args.input.read_bytes()
    normalized = emulate_normalizer(args.image, raw)
    if args.output:
        args.output.write_bytes(normalized)
    print(
        f"input={args.input} raw_size={len(raw)} "
        f"normalized_size={len(normalized)}"
    )
    print(f"head={normalized[:64].hex(' ')}")
    for marker in (b"ServerCost", b"hd1.", b"Ihd1.", b"\x00\x16"):
        positions = []
        offset = 0
        while True:
            offset = normalized.find(marker, offset)
            if offset < 0:
                break
            positions.append(offset)
            offset += 1
        if positions:
            print(
                f"marker={marker!r} offsets="
                + ",".join(f"0x{position:x}" for position in positions)
            )
    if args.output:
        print(f"output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
