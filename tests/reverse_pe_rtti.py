#!/usr/bin/env python
"""Locate 32-bit MSVC RTTI vtables and constructor references in a PE file.

This is an offline reverse-engineering helper for the installed THS binaries.
It does not modify or execute the inspected image.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

import pefile


def occurrences(data: bytes, needle: bytes):
    offset = 0
    while True:
        offset = data.find(needle, offset)
        if offset < 0:
            return
        yield offset
        offset += 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("class_name")
    args = parser.parse_args()

    data = args.image.read_bytes()
    pe = pefile.PE(str(args.image), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    def offset_to_va(offset: int) -> int:
        section = next(
            item
            for item in pe.sections
            if item.PointerToRawData
            <= offset
            < item.PointerToRawData + item.SizeOfRawData
        )
        return (
            image_base
            + section.VirtualAddress
            + offset
            - section.PointerToRawData
        )

    decorated = f".?AV{args.class_name}@@".encode("ascii")
    name_offsets = list(occurrences(data, decorated))
    if not name_offsets:
        decorated = f".?AU{args.class_name}@@".encode("ascii")
        name_offsets = list(occurrences(data, decorated))
    if not name_offsets:
        print(f"RTTI name not found: {args.class_name}")
        return 1

    for name_offset in name_offsets:
        type_offset = name_offset - 8
        type_va = offset_to_va(type_offset)
        print(
            f"type_descriptor: file={type_offset:#x} va={type_va:#x} "
            f"name={decorated.decode()}"
        )

        type_pointer = struct.pack("<I", type_va)
        for ref_offset in occurrences(data, type_pointer):
            # A 32-bit CompleteObjectLocator stores the type descriptor pointer
            # at +0x0c.
            col_offset = ref_offset - 12
            if col_offset < 0:
                continue
            signature, _, _ = struct.unpack_from("<III", data, col_offset)
            if signature != 0:
                continue
            col_va = offset_to_va(col_offset)
            col_pointer = struct.pack("<I", col_va)
            for slot_offset in occurrences(data, col_pointer):
                vtable_offset = slot_offset + 4
                vtable_va = offset_to_va(vtable_offset)
                methods = struct.unpack_from("<8I", data, vtable_offset)
                print(
                    f"  col={col_va:#x} vtable={vtable_va:#x} "
                    f"methods={' '.join(hex(value) for value in methods)}"
                )

                vtable_pointer = struct.pack("<I", vtable_va)
                constructor_refs = [
                    offset_to_va(item)
                    for item in occurrences(data, vtable_pointer)
                    if item != vtable_offset
                ]
                if constructor_refs:
                    print(
                        "    vtable-immediate-refs="
                        + ", ".join(hex(value) for value in constructor_refs)
                    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
