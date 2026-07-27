#!/usr/bin/env python
"""Find direct x86 call/jump sites targeting a virtual address in a PE image."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

import pefile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("target", type=lambda value: int(value, 0))
    args = parser.parse_args()

    data = args.image.read_bytes()
    pe = pefile.PE(str(args.image), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    refs: list[tuple[int, str]] = []

    for section in pe.sections:
        # IMAGE_SCN_MEM_EXECUTE
        if not section.Characteristics & 0x20000000:
            continue
        start = section.PointerToRawData
        raw = data[start : start + section.SizeOfRawData]
        section_va = image_base + section.VirtualAddress
        for index in range(max(0, len(raw) - 4)):
            opcode = raw[index]
            if opcode not in (0xE8, 0xE9):
                continue
            site_va = section_va + index
            displacement = struct.unpack_from("<i", raw, index + 1)[0]
            if site_va + 5 + displacement == args.target:
                refs.append((site_va, "call" if opcode == 0xE8 else "jmp"))

    pointer = struct.pack("<I", args.target)
    offset = 0
    while True:
        offset = data.find(pointer, offset)
        if offset < 0:
            break
        section = next(
            (
                item
                for item in pe.sections
                if item.PointerToRawData
                <= offset
                < item.PointerToRawData + item.SizeOfRawData
            ),
            None,
        )
        if section is not None:
            site_va = (
                image_base
                + section.VirtualAddress
                + offset
                - section.PointerToRawData
            )
            refs.append((site_va, "pointer"))
        offset += 1

    refs.sort()
    for site_va, kind in refs:
        print(f"{site_va:#x} {kind} {args.target:#x}")
    return 0 if refs else 1


if __name__ == "__main__":
    raise SystemExit(main())
