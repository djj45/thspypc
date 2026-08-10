#!/usr/bin/env python
"""Emulate hexin's ``0x7b`` quote-stream normalizer (runtime VA 0xcc9000).

This is deliberately a reverse-engineering oracle, not production code.  It
extracts one stock-depth frame from a pcap, removes the outer command byte
``0x09``, and executes the native decoder from the matching loaded image.

Run with an ephemeral Unicorn dependency::

    uv run --with unicorn python tests/emulate_hexin_7b_normalizer.py \
        captures_live/kanpan_push_20260810_091444.pcap --code-offset 51
"""
from __future__ import annotations

import argparse
import struct
import sys
from collections import deque
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MEM_FETCH_UNMAPPED,
    UC_MODE_32,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_ECX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESI,
    UC_X86_REG_ESP,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture_kanpan_push as capture  # noqa: E402
from reverse_hlib_memory import parse_image  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from thspypc.features.snapshot_protocol import (  # noqa: E402
    is_depth_push,
    is_stock_depth_envelope,
)


NORMALIZER_VA = 0xCC9000
BUFFER_CTOR_VA = 0x1712DD0
NEW_VAS = {0x19F49A0, 0x19F4968}
FREE_VAS = {0x154D550, 0x1B587CB}
MEMCPY_VA = 0x1C21290
MEMSET_VA = 0x1C21F10
SECURITY_COOKIE_VA = 0x1B58D07

PAGE_SIZE = 0x1000
INPUT_BASE = 0x50000000
OUTPUT_OBJECT = 0x51000000
OUTPUT_FLAG = 0x51001000
SESSION_CONTEXT = 0x52000000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x10000000
STACK_BASE = 0x70000000
STACK_SIZE = 0x01000000
RETURN_SENTINEL = 0x71000000


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & -alignment


def stock_code_offset(body: bytes) -> int | None:
    for market_pos in range(5, max(5, len(body) - 6)):
        if body[market_pos] not in (0x11, 0x21):
            continue
        if body[market_pos + 1 : market_pos + 7].isdigit():
            return market_pos + 1
    return None


def extract_sample(pcap: Path, code_offset: int) -> bytes:
    for _timestamp, body, _stream, port in capture._collect_server_frames(pcap):
        if port != "8901":
            continue
        if not is_stock_depth_envelope(body) or is_depth_push(body):
            continue
        if stock_code_offset(body) == code_offset:
            return body[1:]
    raise RuntimeError(f"no unknown depth frame with code offset {code_offset}")


def emulate(
    image_path: Path, encoded: bytes | list[bytes]
) -> tuple[bytes, list[str]]:
    encoded_frames = [encoded] if isinstance(encoded, bytes) else encoded
    if not encoded_frames:
        raise ValueError("at least one encoded frame is required")
    image = parse_image(image_path.read_bytes())
    emulator = Uc(UC_ARCH_X86, UC_MODE_32)
    emulator.mem_map(image.image_base, align_up(image.image_size))
    emulator.mem_write(image.image_base, image.data[: image.image_size])
    emulator.mem_map(INPUT_BASE, align_up(max(map(len, encoded_frames))))
    emulator.mem_map(OUTPUT_OBJECT, 0x2000)
    emulator.mem_map(SESSION_CONTEXT, PAGE_SIZE)
    emulator.mem_write(SESSION_CONTEXT + 0x160, struct.pack("<I", 2))
    emulator.mem_map(HEAP_BASE, HEAP_SIZE)
    emulator.mem_map(STACK_BASE, STACK_SIZE)
    emulator.mem_map(RETURN_SENTINEL, PAGE_SIZE)
    emulator.mem_map(0, PAGE_SIZE)  # fs:[0] for SEH prologues

    heap_next = HEAP_BASE
    dynamic_stubs: dict[int, str] = {}
    dynamic_log: list[str] = []
    unmapped_data_error: list[str] = []
    executed_tail: deque[int] = deque(maxlen=160)
    probe_log: list[str] = []
    record_size_pointer = 0
    bitmask_output_pointer = 0
    bitmask_count_pointer = 0
    normalize_length_pointer = 0

    def stack_args(count: int) -> tuple[int, ...]:
        esp = emulator.reg_read(UC_X86_REG_ESP)
        return struct.unpack(
            "<" + "I" * count, emulator.mem_read(esp + 4, count * 4)
        )

    def return_from_call(value: int | None = None, cleanup: int = 0) -> None:
        esp = emulator.reg_read(UC_X86_REG_ESP)
        return_address = struct.unpack("<I", emulator.mem_read(esp, 4))[0]
        if value is not None:
            emulator.reg_write(UC_X86_REG_EAX, value)
        emulator.reg_write(UC_X86_REG_ESP, esp + 4 + cleanup)
        emulator.reg_write(UC_X86_REG_EIP, return_address)

    def allocate(size: int) -> int:
        nonlocal heap_next
        size = max(16, align_up(size, 16))
        allocation = heap_next
        heap_next += size
        if heap_next > HEAP_BASE + HEAP_SIZE:
            raise MemoryError(f"emulated heap exhausted by allocation 0x{size:x}")
        return allocation

    def code_hook(_uc, address, _size, _user) -> None:
        nonlocal bitmask_count_pointer, bitmask_output_pointer
        nonlocal normalize_length_pointer, record_size_pointer
        executed_tail.append(address)
        if address == 0x18B7860:
            values = stack_args(4)
            probe_log.append(
                "codec_factory args=" + ",".join(f"0x{x:x}" for x in values)
            )
        elif address == 0xCC938A:
            probe_log.append(
                f"codec_factory result=0x{emulator.reg_read(UC_X86_REG_EAX):x}"
            )
        elif address == 0xCCA3B0:
            values = stack_args(5)
            bitmask_output_pointer = values[0]
            bitmask_count_pointer = values[4]
        elif address == 0xCC93BD:
            consumed = emulator.reg_read(UC_X86_REG_EAX)
            count = struct.unpack(
                "<I", emulator.mem_read(bitmask_count_pointer, 4)
            )[0]
            probe_log.append(
                f"selector consumed={consumed} count={count} data="
                f"{bytes(emulator.mem_read(bitmask_output_pointer, count)).hex()}"
            )
        elif address in (0xCC93C8, 0xCC94DC, 0xCC9584, 0xCC95AE):
            current_offset = emulator.reg_read(UC_X86_REG_ESI)
            probe_log.append(
                f"parse_offset site=0x{address:x} offset={current_offset}"
            )
        elif address == 0x172E7D0:
            values = stack_args(5)
            probe_log.append(
                "codec_build args=" + ",".join(f"0x{x:x}" for x in values)
            )
        elif address == 0xCC954E:
            pointer = emulator.reg_read(UC_X86_REG_EAX)
            probe_log.append(
                f"codec_build result=0x{pointer:x} head="
                f"{bytes(emulator.mem_read(pointer, 32)).hex()}"
            )
        elif address == 0xCD5730:
            values = stack_args(6)
            probe_log.append(
                "stream_context args=" + ",".join(f"0x{x:x}" for x in values)
            )
        elif address == 0xCDC420:
            values = stack_args(3)
            normalize_length_pointer = values[2]
            probe_log.append(
                f"delta_normalize input_size={values[1]} head="
                f"{bytes(emulator.mem_read(values[0], min(values[1], 96))).hex()}"
            )
        elif address == 0xCC9663:
            normalized_size = struct.unpack(
                "<I", emulator.mem_read(normalize_length_pointer, 4)
            )[0]
            probe_log.append(
                f"delta_normalize result={emulator.reg_read(UC_X86_REG_EAX)} "
                f"consumed={normalized_size}"
            )
        elif address == 0x16EE0D0:
            values = stack_args(6)
            record_size_pointer = values[5]
            probe_log.append(
                "record_decode args=" + ",".join(f"0x{x:x}" for x in values)
                + " header=" + bytes(emulator.mem_read(values[0], 32)).hex()
                + " context=" + bytes(emulator.mem_read(values[1], values[2])).hex()
                + " buffer=" + bytes(emulator.mem_read(values[3], min(values[4], 96))).hex()
            )
        elif address == 0xCC9706:
            probe_log.append(
                f"record_decode result=0x{emulator.reg_read(UC_X86_REG_EAX):x} "
                f"size={struct.unpack('<I', emulator.mem_read(record_size_pointer, 4))[0]}"
            )
        if address in NEW_VAS:
            return_from_call(allocate(stack_args(1)[0]))
        elif address in FREE_VAS or address == SECURITY_COOKIE_VA:
            return_from_call()
        elif address == MEMCPY_VA:
            destination, source, count = stack_args(3)
            emulator.mem_write(destination, bytes(emulator.mem_read(source, count)))
            return_from_call(destination)
        elif address == MEMSET_VA:
            destination, value, count = stack_args(3)
            emulator.mem_write(destination, bytes([value & 0xFF]) * count)
            return_from_call(destination)
        elif address == RETURN_SENTINEL:
            emulator.emu_stop()
        stub_kind = dynamic_stubs.get(address) or known_dynamic.get(address)
        if stub_kind == "zero_cdecl":
            return_from_call(0)
        elif stub_kind == "zero_std4":
            return_from_call(0, 4)
        elif stub_kind == "thread_id":
            return_from_call(1)
        elif stub_kind == "heap_alloc":
            _heap, _flags, size = stack_args(3)
            return_from_call(allocate(size), 12)
        elif stub_kind == "heap_free":
            return_from_call(1, 12)
        elif stub_kind == "nmc_class":
            # func_sdk_17.dll market::kernal::NMC_CLASS.  The normal market
            # identifiers used by quote pushes encode the class in the low
            # nibble (0x11 -> 1, 0x21 -> 1, 0x90 -> 0).
            return_from_call(stack_args(1)[0] & 0x0F)
        elif stub_kind == "market_from_code":
            code_pointer = stack_args(1)[0]
            first = bytes(emulator.mem_read(code_pointer, 1))[0]
            return_from_call(first if 0x30 <= first <= 0x39 else 0)

    known_dynamic = {
        0x5B97E0D0: "nmc_class",   # func_sdk_17 NMC_CLASS(market)
        0x5B97E140: "market_from_code",  # func_sdk_17 N_GetMarket(code)
        0x75EE3440: "thread_id",   # GetCurrentThreadId()
        0x776EE780: "zero_std4",   # CRT lock helper
        0x776ECB50: "zero_std4",   # CRT unlock helper
        0x75ED5000: "zero_std4",   # LeaveCriticalSection(lock)
        0x779741B0: "zero_std4",   # InitializeCriticalSection(lock)
        0x77973230: "zero_std4",   # DeleteCriticalSection(lock)
        0x7795F670: "heap_alloc",  # HeapAlloc(heap, flags, size)
        0x75ED41B0: "heap_free",   # HeapFree(heap, flags, ptr)
    }

    def fetch_unmapped(_uc, access, address, _size, _value, _user) -> bool:
        if access != UC_MEM_FETCH_UNMAPPED:
            return False
        page = address & -PAGE_SIZE
        try:
            emulator.mem_map(page, PAGE_SIZE)
        except Exception:  # page may already have another generated stub
            pass
        stub_kind = known_dynamic.get(address, "zero_cdecl")
        dynamic_stubs[address] = stub_kind
        esp = emulator.reg_read(UC_X86_REG_ESP)
        caller = struct.unpack("<I", emulator.mem_read(esp, 4))[0]
        args = struct.unpack("<III", emulator.mem_read(esp + 4, 12))
        dynamic_log.append(
            f"0x{address:08x} from 0x{caller:08x} {stub_kind} "
            f"args={','.join(f'0x{x:x}' for x in args)}"
        )
        emulator.mem_write(address, b"\x90")
        return True

    def data_unmapped(_uc, access, address, size, _value, _user) -> bool:
        eip = emulator.reg_read(UC_X86_REG_EIP)
        unmapped_data_error.append(
            f"unmapped data access={access} address=0x{address:x} size={size} "
            f"eip=0x{eip:x}"
        )
        return False

    emulator.hook_add(UC_HOOK_CODE, code_hook)
    emulator.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, fetch_unmapped)
    emulator.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, data_unmapped
    )

    stack_pointer = STACK_BASE + STACK_SIZE - 0x100
    emulator.mem_write(
        stack_pointer, struct.pack("<II", RETURN_SENTINEL, 0x1000)
    )
    emulator.reg_write(UC_X86_REG_ESP, stack_pointer)
    emulator.reg_write(UC_X86_REG_ECX, OUTPUT_OBJECT)
    emulator.reg_write(UC_X86_REG_EIP, BUFFER_CTOR_VA)
    emulator.emu_start(
        BUFFER_CTOR_VA, RETURN_SENTINEL + 1, timeout=30_000_000, count=10_000_000
    )

    normalized = b""
    success = 0
    data = size = capacity = 0
    for frame_index, current in enumerate(encoded_frames):
        emulator.mem_write(INPUT_BASE, current)
        # Preserve the allocated buffer/capacity, but discard the prior
        # frame's bytes.  Global codec registrations intentionally survive.
        emulator.mem_write(OUTPUT_OBJECT + 8, b"\0" * 4)
        emulator.mem_write(OUTPUT_FLAG, b"\0" * 16)
        emulator.mem_write(
            stack_pointer,
            struct.pack(
                "<IIIIII",
                RETURN_SENTINEL,
                INPUT_BASE,
                len(current),
                OUTPUT_OBJECT,
                SESSION_CONTEXT,
                OUTPUT_FLAG,
            ),
        )
        emulator.reg_write(UC_X86_REG_ESP, stack_pointer)
        emulator.reg_write(UC_X86_REG_ECX, 0)
        emulator.reg_write(UC_X86_REG_EIP, NORMALIZER_VA)
        try:
            emulator.emu_start(
                NORMALIZER_VA,
                RETURN_SENTINEL + 1,
                timeout=120_000_000,
                count=100_000_000,
            )
        except Exception as exc:
            eip = emulator.reg_read(UC_X86_REG_EIP)
            esp = emulator.reg_read(UC_X86_REG_ESP)
            details = unmapped_data_error[-1] if unmapped_data_error else str(exc)
            raise RuntimeError(
                f"native emulation frame {frame_index} stopped at "
                f"eip=0x{eip:x}, esp=0x{esp:x}: {details}; "
                f"dynamic stubs={dynamic_log}"
            ) from exc

        success = emulator.reg_read(UC_X86_REG_EAX)
        data, size, capacity = struct.unpack(
            "<III", emulator.mem_read(OUTPUT_OBJECT + 4, 12)
        )
        if size:
            normalized = bytes(emulator.mem_read(data, size))

    # cc9000 returns zero after both a successful conversion and a rejected
    # frame; the dynamic output buffer is the authoritative result.  A
    # successful built-in frame was observed with eax=0 and size=361.
    if size == 0:
        raise RuntimeError(
            f"native 0x7b normalizer returned {success}; size={size}, "
            f"capacity={capacity}; flag="
            f"{bytes(emulator.mem_read(OUTPUT_FLAG, 8)).hex()}; tail="
            f"{','.join(f'0x{x:08x}' for x in executed_tail)}; "
            f"probes={probe_log}; dynamic stubs={dynamic_log}"
        )
    return normalized, [*probe_log, *dynamic_log]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--code-offset", type=int, default=51)
    parser.add_argument(
        "--image",
        type=Path,
        default=Path("captures_live/hexin.dmp.loaded.bin"),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    encoded = extract_sample(args.pcap, args.code_offset)
    normalized, dynamic_log = emulate(args.image, encoded)
    print(
        f"encoded={len(encoded)} normalized={len(normalized)} "
        f"head={normalized[:64].hex(' ')}"
    )
    for line in dynamic_log:
        print(f"stub {line}")
    if args.output:
        args.output.write_bytes(normalized)
        print(f"output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
