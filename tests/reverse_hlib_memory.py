#!/usr/bin/env python
"""Find string anchors and x86 code references in a loaded hlib image dump.

The hlib 2.3.4 on-disk PE is VMProtect-packed: its ordinary code and data
sections have no raw bytes.  The x86 harness dumps the post-LoadLibrary memory
image with bytes stored at their RVAs.  This tool parses that virtual layout,
finds selected ASCII anchors, and uses Capstone to report direct code
references to their virtual addresses.

Usage:
    py tests/reverse_hlib_memory.py \
        captures_live/hlib_2.3.4.memory.bin \
        --needle hd1. --needle CHQuoteFile
"""
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM


IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)


@dataclass(frozen=True)
class Image:
    data: bytes
    image_base: int
    image_size: int
    sections: tuple[Section, ...]


def parse_image(data: bytes) -> Image:
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("input is not an MZ image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("PE signature not found")

    file_header = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, file_header)
    if machine != 0x14C:
        raise ValueError(f"expected x86 machine 0x14c, got 0x{machine:x}")
    optional_size = struct.unpack_from("<H", data, file_header + 16)[0]
    optional = file_header + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic != 0x10B:
        raise ValueError(f"expected PE32 optional header, got 0x{magic:x}")

    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    image_size = struct.unpack_from("<I", data, optional + 56)[0]
    if image_size > len(data):
        raise ValueError(
            f"dump is truncated: image_size=0x{image_size:x}, bytes=0x{len(data):x}"
        )

    sections: list[Section] = []
    section_table = optional + optional_size
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode(
            "ascii", errors="replace"
        )
        virtual_size, virtual_address = struct.unpack_from("<II", data, offset + 8)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        sections.append(
            Section(name, virtual_address, virtual_size, characteristics)
        )
    return Image(data, image_base, image_size, tuple(sections))


def find_all(data: bytes, needle: bytes) -> list[int]:
    matches: list[int] = []
    offset = 0
    while True:
        offset = data.find(needle, offset)
        if offset < 0:
            return matches
        matches.append(offset)
        offset += 1


def executable_ranges(
    image: Image, all_executable: bool
) -> list[tuple[int, int]]:
    ranges = []
    for section in image.sections:
        if (
            not section.executable
            or section.virtual_size == 0
            or (not all_executable and section.name != ".text")
        ):
            continue
        start = section.virtual_address
        end = min(start + section.virtual_size, len(image.data))
        ranges.append((start, end))
    return ranges


def fast_xrefs(
    image: Image,
    targets: set[int],
    immediates: set[int],
    all_executable: bool,
) -> list[tuple[int, str, int]]:
    """Find likely xrefs without disassembling the whole executable image."""
    references: set[tuple[int, str, int]] = set()
    absolute_values = targets | immediates
    for start, end in executable_ranges(image, all_executable):
        section_data = image.data[start:end]
        for value in absolute_values:
            encodings = [("absolute", struct.pack("<I", value & 0xFFFFFFFF))]
            if 0 <= value <= 0xFFFF:
                encodings.append(("immediate16", struct.pack("<H", value)))
            for kind, encoded in encodings:
                for offset in find_all(section_data, encoded):
                    references.add((start + offset, kind, value))

        for opcode, kind in ((b"\xe8", "call"), (b"\xe9", "jump")):
            search_from = 0
            while True:
                offset = section_data.find(opcode, search_from)
                if offset < 0:
                    break
                if offset + 5 <= len(section_data):
                    rva = start + offset
                    relative = struct.unpack_from(
                        "<i", section_data, offset + 1
                    )[0]
                    target = image.image_base + rva + 5 + relative
                    if target in targets:
                        references.add((rva, kind, target))
                search_from = offset + 1
    return sorted(references)


def direct_xrefs(
    image: Image,
    targets: set[int],
    immediates: set[int],
    all_executable: bool,
) -> list[tuple[int, str, str, str]]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoder.skipdata = True
    references: list[tuple[int, str, str, str]] = []
    for section in image.sections:
        if (
            not section.executable
            or section.virtual_size == 0
            or (not all_executable and section.name != ".text")
        ):
            continue
        start = section.virtual_address
        end = min(start + section.virtual_size, len(image.data))
        for instruction in decoder.disasm(
            image.data[start:end], image.image_base + start
        ):
            if instruction.id == 0:
                continue
            referenced = False
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM and (
                    operand.imm in targets or operand.imm in immediates
                ):
                    referenced = True
                elif operand.type == X86_OP_MEM and operand.mem.disp in targets:
                    referenced = True
            if referenced:
                references.append(
                    (
                        instruction.address - image.image_base,
                        instruction.bytes.hex(" "),
                        instruction.mnemonic,
                        instruction.op_str,
                    )
                )
    return references


def byte_comparisons(
    image: Image,
    value: int,
    all_executable: bool,
) -> list[tuple[int, str, str, str]]:
    """Find x86 ``cmp r/m8, imm8`` instructions without decoding whole sections."""
    if not 0 <= value <= 0xFF:
        raise ValueError(f"byte comparison value is out of range: 0x{value:x}")

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    references: list[tuple[int, str, str, str]] = []
    for start, end in executable_ranges(image, all_executable):
        section_data = image.data[start:end]
        for opcode in (0x3C, 0x80):
            search_from = 0
            encoded = bytes([opcode])
            while True:
                offset = section_data.find(encoded, search_from)
                if offset < 0:
                    break
                instructions = list(
                    decoder.disasm(
                        section_data[offset:offset + 15],
                        image.image_base + start + offset,
                        count=1,
                    )
                )
                if instructions:
                    instruction = instructions[0]
                    operands = instruction.operands
                    if (
                        instruction.mnemonic == "cmp"
                        and len(operands) == 2
                        and operands[0].size == 1
                        and operands[1].type == X86_OP_IMM
                        and (operands[1].imm & 0xFF) == value
                    ):
                        references.append(
                            (
                                instruction.address - image.image_base,
                                instruction.bytes.hex(" "),
                                instruction.mnemonic,
                                instruction.op_str,
                            )
                        )
                search_from = offset + 1
    return references


def disassemble_window(image: Image, rva: int, size: int) -> None:
    if rva < 0 or rva >= len(image.data):
        raise ValueError(f"disassembly RVA is outside the image: 0x{rva:x}")
    end = min(rva + size, len(image.data))
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.skipdata = True
    for instruction in decoder.disasm(
        image.data[rva:end], image.image_base + rva
    ):
        current_rva = instruction.address - image.image_base
        if instruction.id == 0:
            print(
                f"  0x{current_rva:08x}  {instruction.bytes.hex(' '):<24} "
                "<data>"
            )
            continue
        print(
            f"  0x{current_rva:08x}  {instruction.bytes.hex(' '):<24} "
            f"{instruction.mnemonic:<8} {instruction.op_str}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dump", type=Path)
    parser.add_argument(
        "--needle",
        action="append",
        default=[],
        help="ASCII string to find; may be passed more than once",
    )
    parser.add_argument(
        "--no-default-needles",
        action="store_true",
        help="do not search for the default hd1./CHQuoteFile anchors",
    )
    parser.add_argument(
        "--inline-immediates",
        action="store_true",
        help="also treat four-byte chunks of each needle as xref targets",
    )
    parser.add_argument(
        "--all-executable",
        action="store_true",
        help="also scan VMProtect executable sections; .text is the default",
    )
    parser.add_argument(
        "--fast-xrefs",
        action="store_true",
        help=(
            "scan rel32 calls/jumps and little-endian addresses instead of "
            "disassembling entire executable sections"
        ),
    )
    parser.add_argument(
        "--disasm-rva",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="disassemble a window beginning at this RVA",
    )
    parser.add_argument(
        "--disasm-size",
        type=lambda value: int(value, 0),
        default=0x100,
    )
    parser.add_argument(
        "--xref-rva",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="find direct code references to this RVA",
    )
    parser.add_argument(
        "--immediate",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="find code containing this numeric immediate",
    )
    parser.add_argument(
        "--compare-byte",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="find cmp instructions comparing a byte operand with this value",
    )
    args = parser.parse_args()
    if args.needle:
        needles = args.needle
    elif args.no_default_needles:
        needles = []
    else:
        needles = ["hd1.", "CHQuoteFile"]

    image = parse_image(args.dump.read_bytes())
    print(
        f"image_base=0x{image.image_base:08x} "
        f"image_size=0x{image.image_size:x}"
    )
    for section in image.sections:
        flags = "X" if section.executable else "-"
        print(
            f"section {section.name:8} rva=0x{section.virtual_address:08x} "
            f"size=0x{section.virtual_size:x} {flags}"
        )

    for text in needles:
        needle = text.encode("ascii")
        matches = find_all(image.data, needle)
        targets = {image.image_base + rva for rva in matches}
        immediates = (
            {
                int.from_bytes(needle[offset:offset + 4], "little")
                for offset in range(max(0, len(needle) - 3))
            }
            if args.inline_immediates
            else set()
        )
        print(
            f"\nneedle={text!r} matches="
            + (", ".join(f"0x{rva:x}" for rva in matches) or "none")
        )
        if args.fast_xrefs:
            references = fast_xrefs(
                image, targets, immediates, args.all_executable
            )
        else:
            references = direct_xrefs(
                image, targets, immediates, args.all_executable
            )
        if not references:
            print("  direct code xrefs: none")
            continue
        if args.fast_xrefs:
            for rva, kind, value in references:
                print(
                    f"  xref rva=0x{rva:08x} kind={kind:<8} "
                    f"value=0x{value:08x}"
                )
        else:
            for rva, raw, mnemonic, operands in references:
                print(
                    f"  xref rva=0x{rva:08x} bytes={raw:<24} "
                    f"{mnemonic} {operands}"
                )
    for target_rva in args.xref_rva:
        target = image.image_base + target_rva
        print(f"\ntarget_rva=0x{target_rva:x} target_va=0x{target:08x}")
        if args.fast_xrefs:
            references = fast_xrefs(
                image, {target}, set(), args.all_executable
            )
        else:
            references = direct_xrefs(
                image, {target}, set(), args.all_executable
            )
        if not references:
            print("  direct code xrefs: none")
        if args.fast_xrefs:
            for rva, kind, value in references:
                print(
                    f"  xref rva=0x{rva:08x} kind={kind:<8} "
                    f"value=0x{value:08x}"
                )
        else:
            for rva, raw, mnemonic, operands in references:
                print(
                    f"  xref rva=0x{rva:08x} bytes={raw:<24} "
                    f"{mnemonic} {operands}"
                )
    for immediate in args.immediate:
        print(f"\nimmediate=0x{immediate:x}")
        if args.fast_xrefs:
            references = fast_xrefs(
                image, set(), {immediate}, args.all_executable
            )
        else:
            references = direct_xrefs(
                image, set(), {immediate}, args.all_executable
            )
        if not references:
            print("  code references: none")
        if args.fast_xrefs:
            for rva, kind, value in references:
                print(
                    f"  xref rva=0x{rva:08x} kind={kind:<11} "
                    f"value=0x{value:08x}"
                )
        else:
            for rva, raw, mnemonic, operands in references:
                print(
                    f"  xref rva=0x{rva:08x} bytes={raw:<24} "
                    f"{mnemonic} {operands}"
                )
    for value in args.compare_byte:
        print(f"\ncompare_byte=0x{value:02x}")
        references = byte_comparisons(image, value, args.all_executable)
        if not references:
            print("  code comparisons: none")
        for rva, raw, mnemonic, operands in references:
            print(
                f"  cmp rva=0x{rva:08x} bytes={raw:<24} "
                f"{mnemonic} {operands}"
            )
    for rva in args.disasm_rva:
        print(f"\ndisassembly rva=0x{rva:x} size=0x{args.disasm_size:x}")
        disassemble_window(image, rva, args.disasm_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
