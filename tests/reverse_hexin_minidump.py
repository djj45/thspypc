#!/usr/bin/env python
"""Inspect and extract a module from a Windows minidump.

The installed hexin.exe uses an UPX layout whose unpacked code is absent from
the on-disk UPX0 section. A full Task Manager dump contains the loaded image.
This tool reads the dump through mmap, so multi-gigabyte files are not copied
into Python memory.

Examples:
    py tests/reverse_hexin_minidump.py info C:\\path\\hexin.DMP \
        --module hexin.exe --rva 0x127c8b0

    py tests/reverse_hexin_minidump.py extract-module C:\\path\\hexin.DMP \
        --module hexin.exe --output captures_live\\hexin.loaded.bin

    py tests/reverse_hexin_minidump.py search C:\\path\\hexin.DMP \
        --ascii "pageid=4214" --ascii "DateTime=7176"

    py tests/reverse_hexin_minidump.py search C:\\path\\hexin.DMP \
        --file captures_live\\auction_raw.bin --file-offset 0x2b \
        --file-size 64
"""
from __future__ import annotations

import argparse
import json
import mmap
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


MINIDUMP_SIGNATURE = b"MDMP"
MODULE_LIST_STREAM = 4
MEMORY_LIST_STREAM = 5
MEMORY_64_LIST_STREAM = 9
MODULE_RECORD_SIZE = 108


@dataclass(frozen=True)
class StreamDirectory:
    stream_type: int
    data_size: int
    rva: int


@dataclass(frozen=True)
class Module:
    base: int
    size: int
    checksum: int
    timestamp: int
    name: str

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass(frozen=True)
class MemoryRange:
    start: int
    size: int
    file_offset: int

    @property
    def end(self) -> int:
        return self.start + self.size


class Minidump:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._file: BinaryIO | None = None
        self._mapping: mmap.mmap | None = None
        self.directories: dict[int, StreamDirectory] = {}
        self.modules: tuple[Module, ...] = ()
        self.memory_ranges: tuple[MemoryRange, ...] = ()
        self.flags = 0

    def __enter__(self) -> "Minidump":
        self._file = self.path.open("rb")
        self._mapping = mmap.mmap(
            self._file.fileno(), length=0, access=mmap.ACCESS_READ
        )
        self._parse()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._mapping is not None:
            self._mapping.close()
            self._mapping = None
        if self._file is not None:
            self._file.close()
            self._file = None

    @property
    def data(self) -> mmap.mmap:
        if self._mapping is None:
            raise RuntimeError("minidump is not open")
        return self._mapping

    def _require_bounds(self, offset: int, size: int, label: str) -> None:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError(
                f"{label} is outside the dump: "
                f"offset=0x{offset:x}, size=0x{size:x}"
            )

    def _parse(self) -> None:
        self._require_bounds(0, 32, "header")
        (
            signature,
            _version,
            stream_count,
            directory_rva,
            _checksum,
            _timestamp,
            self.flags,
        ) = struct.unpack_from("<4sIIIIIQ", self.data, 0)
        if signature != MINIDUMP_SIGNATURE:
            raise ValueError(f"not a minidump: signature={signature!r}")

        self._require_bounds(
            directory_rva, stream_count * 12, "stream directory"
        )
        directories: dict[int, StreamDirectory] = {}
        for index in range(stream_count):
            offset = directory_rva + index * 12
            stream_type, data_size, rva = struct.unpack_from(
                "<III", self.data, offset
            )
            self._require_bounds(rva, data_size, f"stream {stream_type}")
            directories[stream_type] = StreamDirectory(
                stream_type, data_size, rva
            )
        self.directories = directories
        self.modules = self._parse_modules()
        self.memory_ranges = self._parse_memory_ranges()

    def _read_minidump_string(self, rva: int) -> str:
        self._require_bounds(rva, 4, "MINIDUMP_STRING length")
        byte_length = struct.unpack_from("<I", self.data, rva)[0]
        self._require_bounds(rva + 4, byte_length, "MINIDUMP_STRING data")
        raw = self.data[rva + 4:rva + 4 + byte_length]
        return raw.decode("utf-16le", errors="replace")

    def _parse_modules(self) -> tuple[Module, ...]:
        directory = self.directories.get(MODULE_LIST_STREAM)
        if directory is None:
            return ()
        self._require_bounds(directory.rva, 4, "module count")
        count = struct.unpack_from("<I", self.data, directory.rva)[0]
        records_rva = directory.rva + 4
        self._require_bounds(
            records_rva, count * MODULE_RECORD_SIZE, "module records"
        )

        modules: list[Module] = []
        seen: set[tuple[int, int, str]] = set()
        for index in range(count):
            offset = records_rva + index * MODULE_RECORD_SIZE
            base, size, checksum, timestamp, name_rva = struct.unpack_from(
                "<QIIII", self.data, offset
            )
            name = self._read_minidump_string(name_rva)
            identity = (base, size, name.casefold())
            if identity in seen:
                continue
            seen.add(identity)
            modules.append(Module(base, size, checksum, timestamp, name))
        return tuple(modules)

    def _parse_memory_ranges(self) -> tuple[MemoryRange, ...]:
        directory = self.directories.get(MEMORY_64_LIST_STREAM)
        if directory is not None:
            self._require_bounds(directory.rva, 16, "Memory64List header")
            count, data_rva = struct.unpack_from(
                "<QQ", self.data, directory.rva
            )
            descriptors_rva = directory.rva + 16
            self._require_bounds(
                descriptors_rva, count * 16, "Memory64List descriptors"
            )

            ranges: list[MemoryRange] = []
            file_offset = data_rva
            for index in range(count):
                offset = descriptors_rva + index * 16
                start, size = struct.unpack_from("<QQ", self.data, offset)
                self._require_bounds(
                    file_offset, size, f"Memory64 range {index}"
                )
                ranges.append(MemoryRange(start, size, file_offset))
                file_offset += size
            return tuple(sorted(ranges, key=lambda item: item.start))

        directory = self.directories.get(MEMORY_LIST_STREAM)
        if directory is None:
            return ()
        self._require_bounds(directory.rva, 4, "MemoryList count")
        count = struct.unpack_from("<I", self.data, directory.rva)[0]
        descriptors_rva = directory.rva + 4
        self._require_bounds(
            descriptors_rva, count * 16, "MemoryList descriptors"
        )
        ranges = []
        for index in range(count):
            offset = descriptors_rva + index * 16
            start, size, rva = struct.unpack_from("<QII", self.data, offset)
            self._require_bounds(rva, size, f"MemoryList range {index}")
            ranges.append(MemoryRange(start, size, rva))
        return tuple(sorted(ranges, key=lambda item: item.start))

    def find_modules(self, name: str) -> list[Module]:
        wanted = name.casefold()
        return [
            module
            for module in self.modules
            if Path(module.name).name.casefold() == wanted
        ]

    def module(self, name: str) -> Module:
        matches = self.find_modules(name)
        if not matches:
            raise ValueError(f"module not found in dump: {name}")
        if len(matches) > 1:
            bases = ", ".join(f"0x{item.base:x}" for item in matches)
            raise ValueError(f"module name is ambiguous ({bases}): {name}")
        return matches[0]

    def ranges_for(self, start: int, size: int) -> list[MemoryRange]:
        end = start + size
        return [
            item
            for item in self.memory_ranges
            if item.start < end and item.end > start
        ]

    def module_for_address(self, address: int) -> Module | None:
        return next(
            (
                module
                for module in self.modules
                if module.base <= address < module.end
            ),
            None,
        )

    def search_virtual(
        self, pattern: bytes, max_matches: int
    ) -> list[tuple[int, MemoryRange]]:
        if not pattern:
            raise ValueError("search pattern must not be empty")
        matches: list[tuple[int, MemoryRange]] = []
        for item in self.memory_ranges:
            range_end = item.file_offset + item.size
            cursor = item.file_offset
            while len(matches) < max_matches:
                found = self.data.find(pattern, cursor, range_end)
                if found < 0:
                    break
                address = item.start + found - item.file_offset
                matches.append((address, item))
                cursor = found + 1
            if len(matches) >= max_matches:
                break
        return matches

    def read_virtual(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must not be negative")
        end = address + size
        cursor = address
        chunks: list[bytes] = []
        for item in self.ranges_for(address, size):
            overlap_start = max(cursor, item.start)
            overlap_end = min(end, item.end)
            if overlap_start > cursor:
                raise ValueError(
                    f"virtual memory gap at 0x{cursor:x}-0x{overlap_start:x}"
                )
            if overlap_end <= overlap_start:
                continue
            file_offset = item.file_offset + overlap_start - item.start
            chunks.append(
                self.data[file_offset:file_offset + overlap_end - overlap_start]
            )
            cursor = overlap_end
            if cursor == end:
                break
        if cursor != end:
            raise ValueError(f"virtual memory is missing at 0x{cursor:x}")
        return b"".join(chunks)

    def extract_module(self, module: Module, output: Path) -> dict[str, int]:
        ranges = self.ranges_for(module.base, module.size)
        output.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with output.open("wb") as destination:
            destination.truncate(module.size)
            for item in ranges:
                overlap_start = max(module.base, item.start)
                overlap_end = min(module.end, item.end)
                if overlap_end <= overlap_start:
                    continue
                size = overlap_end - overlap_start
                file_offset = item.file_offset + overlap_start - item.start
                destination.seek(overlap_start - module.base)
                destination.write(self.data[file_offset:file_offset + size])
                written += size
        return {
            "module_size": module.size,
            "bytes_written": written,
            "bytes_missing": module.size - written,
            "range_count": len(ranges),
        }


def module_to_dict(module: Module) -> dict[str, str | int]:
    return {
        "name": module.name,
        "base": f"0x{module.base:08x}",
        "size": module.size,
        "size_hex": f"0x{module.size:x}",
        "end": f"0x{module.end:08x}",
        "timestamp": f"0x{module.timestamp:08x}",
        "checksum": f"0x{module.checksum:08x}",
    }


def command_info(args: argparse.Namespace) -> int:
    with Minidump(args.dump) as dump:
        result: dict[str, object] = {
            "dump": str(args.dump.resolve()),
            "dump_size": args.dump.stat().st_size,
            "flags": f"0x{dump.flags:x}",
            "stream_types": sorted(dump.directories),
            "module_count": len(dump.modules),
            "memory_range_count": len(dump.memory_ranges),
        }
        if args.module:
            module = dump.module(args.module)
            result["module"] = module_to_dict(module)
            inspections = []
            for rva in args.rva:
                address = module.base + rva
                try:
                    raw = dump.read_virtual(address, args.read_size)
                    inspections.append(
                        {
                            "rva": f"0x{rva:x}",
                            "address": f"0x{address:x}",
                            "bytes": raw.hex(" "),
                        }
                    )
                except ValueError as error:
                    inspections.append(
                        {
                            "rva": f"0x{rva:x}",
                            "address": f"0x{address:x}",
                            "error": str(error),
                        }
                    )
            if inspections:
                result["inspections"] = inspections
        else:
            result["modules"] = [
                module_to_dict(module) for module in dump.modules
            ]
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def command_extract_module(args: argparse.Namespace) -> int:
    with Minidump(args.dump) as dump:
        module = dump.module(args.module)
        stats = dump.extract_module(module, args.output)
        result = {
            "dump": str(args.dump.resolve()),
            "output": str(args.output.resolve()),
            "module": module_to_dict(module),
            **stats,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if stats["bytes_missing"] == 0 else 2


def _parse_hex_pattern(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _search_patterns(args: argparse.Namespace) -> list[tuple[str, bytes]]:
    patterns = [
        (f"ascii:{value}", value.encode("utf-8")) for value in args.ascii
    ]
    patterns.extend(
        (f"hex:{value.hex()}", value) for value in args.hex_pattern
    )
    for path in args.file:
        raw = path.read_bytes()
        start = args.file_offset
        if start > len(raw):
            raise ValueError(
                f"file offset 0x{start:x} exceeds {path} size 0x{len(raw):x}"
            )
        end = len(raw)
        if args.file_size is not None:
            end = min(end, start + args.file_size)
        patterns.append(
            (
                f"file:{path.resolve()}[0x{start:x}:0x{end:x}]",
                raw[start:end],
            )
        )
    if not patterns:
        raise ValueError("provide at least one --ascii, --hex, or --file")
    return patterns


def command_search(args: argparse.Namespace) -> int:
    patterns = _search_patterns(args)
    with Minidump(args.dump) as dump:
        results = []
        for label, pattern in patterns:
            matches = []
            for address, memory_range in dump.search_virtual(
                pattern, args.max_matches
            ):
                match_offset = memory_range.file_offset + (
                    address - memory_range.start
                )
                context_start = max(
                    memory_range.file_offset, match_offset - args.context
                )
                context_end = min(
                    memory_range.file_offset + memory_range.size,
                    match_offset + len(pattern) + args.context,
                )
                context = bytes(dump.data[context_start:context_end])
                module = dump.module_for_address(address)
                item: dict[str, object] = {
                    "address": f"0x{address:08x}",
                    "memory_range": (
                        f"0x{memory_range.start:08x}-"
                        f"0x{memory_range.end:08x}"
                    ),
                    "dump_offset": f"0x{match_offset:x}",
                    "context_hex": context.hex(" "),
                    "context_ascii": "".join(
                        chr(value) if 0x20 <= value < 0x7F else "."
                        for value in context
                    ),
                }
                if module is not None:
                    item["module"] = Path(module.name).name
                    item["module_rva"] = f"0x{address - module.base:x}"
                matches.append(item)
            results.append(
                {
                    "pattern": label,
                    "size": len(pattern),
                    "match_count": len(matches),
                    "limited": len(matches) == args.max_matches,
                    "matches": matches,
                }
            )
        print(
            json.dumps(
                {
                    "dump": str(args.dump.resolve()),
                    "results": results,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    info = subparsers.add_parser("info")
    info.add_argument("dump", type=Path)
    info.add_argument("--module")
    info.add_argument(
        "--rva",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
    )
    info.add_argument(
        "--read-size",
        type=lambda value: int(value, 0),
        default=32,
    )
    info.set_defaults(handler=command_info)

    extract = subparsers.add_parser("extract-module")
    extract.add_argument("dump", type=Path)
    extract.add_argument("--module", required=True)
    extract.add_argument("--output", required=True, type=Path)
    extract.set_defaults(handler=command_extract_module)

    search = subparsers.add_parser("search")
    search.add_argument("dump", type=Path)
    search.add_argument("--ascii", action="append", default=[])
    search.add_argument(
        "--hex",
        dest="hex_pattern",
        action="append",
        type=_parse_hex_pattern,
        default=[],
    )
    search.add_argument("--file", action="append", type=Path, default=[])
    search.add_argument(
        "--file-offset",
        type=lambda value: int(value, 0),
        default=0,
    )
    search.add_argument(
        "--file-size",
        type=lambda value: int(value, 0),
    )
    search.add_argument(
        "--max-matches",
        type=lambda value: int(value, 0),
        default=32,
    )
    search.add_argument(
        "--context",
        type=lambda value: int(value, 0),
        default=32,
    )
    search.set_defaults(handler=command_search)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
