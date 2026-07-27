#!/usr/bin/env python
"""Find ASCII strings and absolute 32-bit references in an offline PE image."""
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
    parser.add_argument("text")
    args = parser.parse_args()

    data = args.image.read_bytes()
    pe = pefile.PE(str(args.image), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    def offset_to_va(offset: int) -> int:
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
        if section is None:
            raise ValueError(f"file offset is outside PE sections: {offset:#x}")
        return image_base + section.VirtualAddress + offset - section.PointerToRawData

    needle = args.text.encode("utf-8")
    found = False
    for string_offset in occurrences(data, needle):
        found = True
        string_va = offset_to_va(string_offset)
        refs = [
            offset_to_va(offset)
            for offset in occurrences(data, struct.pack("<I", string_va))
        ]
        print(
            f"string: file={string_offset:#x} va={string_va:#x} "
            f"refs={', '.join(hex(value) for value in refs) or '-'}"
        )
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(main())
