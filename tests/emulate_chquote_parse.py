"""用 Unicorn 跑 CHQuoteFile 构造函数 + parse，并可主动调用 parse 后消费者探针。

策略（playbook §8）：
1. 分配一块大内存当 CHQuoteFile this 对象；
2. 跑构造函数 0x127c570 初始化对象（ecx=this + 参数）；
3. 跑 parse 0x127c8b0（ecx=this + 记录区指针参数）；
4. 可选调用真实上层调用点使用的 post-parse helper，并监控其对记录缓冲的读取。

参数 ABI 来自反汇编：
- 构造函数 0x127c570：__thiscall，ecx=this，栈参数 4 个（从 0x127ca60 ret 0x10 推断）。
- parse 0x127c8b0：__thiscall，ecx=this，ret 0xc（3 个栈参数 × 4）。
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from reverse_hlib_memory import parse_image  # noqa: E402

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_MODE_32, Uc  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_EAX,
    UC_X86_REG_EBP,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESI,
    UC_X86_REG_ESP,
    UC_X86_REG_FS,
    UC_X86_REG_GDTR,
)


CTOR_RVA = 0x127C570
PARSE_RVA = 0x127C8B0
RECORD_DECODER_RVA = 0x136BBE0  # esi==1 分支的记录解码器
MALLOC_VA = 0x2332BA2
FREE_VA = 0x23310D9
MEMCPY_VA = 0x2321290
# 第二个 memcpy 副本（与 MEMCPY_VA 逐字节相同）。0x136c080 的 type==0 字段拷贝
# 走这个地址，必须一并 hook，否则 esi==2 路径的字段拷贝全部漏抓。
MEMCPY2_VA = 0x2321810
MEMSET_VA = 0x2321F10
OPERATOR_NEW_VA = 0x20F49A0
SECURITY_COOKIE_VA = 0x2C14F3C  # __security_cookie

# CHQuoteFile 的两个真实上层调用者在 parse 成功后调用这两个 helper。它们先读取
# 表/字段元数据，再通过 CHQuoteFile::for_each(0x127ca30) 枚举行。二者的 ABI 均为：
#   cdecl helper(CHQuoteFile *quote, int *out_count) -> array*
# 0x127c6a0（vtable+0x48）已确认是 close/reset 清理路径，不得当 getter 调用。
POST_PARSE_PROBES = {
    "schema1c": 0x10E1500,  # caller 0xa6abb1，输出元素宽 0x1c
    "schema38": 0x10E1670,  # caller 0xaa415d，输出元素宽 0x38
}

# --- 0x136c080（esi==2 字段解析器）字段类型分发插桩用 RVA ---
# 每次调用处理一个字段，由调用者 0x136c390 逐字段驱动。描述符布局：
# [esi+0]=type 字节、[esi+0xc]=步长1、[esi+0x10]=步长2、[esi+0x1c]=数据长度。
TYPE_READ_RVA = 0x136C164  # movzx eax,[esi]；hook 此点时 esi 已就绪，读 [esi+0]=type
# 四个字段拷贝/解码 call site（call 指令所在地址）。
MEMCPY_FIELD_CALLSITE = 0x136C182  # type==0 -> 0x2321810；抓 EBX(src)/EDX(len)/[ebp+0x10](dst)
DECODER_T3_CALLSITE = 0x136C1CC   # type==3 -> 0x139bbb0
DECODER_T56_CALLSITE = 0x136C209  # type==5/6 -> 0x139bd50
DECODER_T12_CALLSITE = 0x136C230  # type==1/2 -> 0x139a800

# --- parse(0x127c8b0) 分支硬断言用的 RVA（见 CORRECTION 交接文档 §四）---
# parse 调分类器 0x136c430，返回值经两处 mov esi,eax 进入 esi，再在 dispatch 处
# test esi,esi / cmp esi,2 / cmp esi,1 做 switch：esi==2 -> 0x136c390（期望路径），
# esi==1 -> 0x136bbe0（STEP2 误判、本样本不应走）。
CLASSIFIER_RVA = 0x136C430
# dispatch 入口：到达此指令时 ESI 即分类结果。hook 在指令前触发，读 ESI 取真值。
PARSE_DISPATCH_RVA = 0x127C955
# 两处 mov esi,eax：hook 在指令前触发时 EAX 即分类器返回值。
PARSE_READ_EAX_AFTER_CLASSIFY = (0x127C8FD, 0x127C940)
# parse 内三个 call site（esi==0/1/2 分发目标）。
PARSE_CALL_ESI0_SITE = 0x127C95B  # call 0x127ce20
PARSE_CALL_ESI1_SITE = 0x127C97F  # call 0x136bbe0 —— 不应命中
PARSE_CALL_ESI2_SITE = 0x127C96D  # call 0x136c390 —— 期望命中
# esi==2 分支入口及其内部 call 的核心解析器（0x136c390 内 0x136c3b6 处 call 0x136c080）。
ESI2_ENTRY_RVA = 0x136C390
ESI2_CORE_RVA = 0x136C080
# STEP2 声称的「记录解码全链」函数。当前 esi==2 样本不应命中任何一个。
FORBIDDEN_RVAS = (0x136BBE0, 0x136B8E0, 0x139A6D0, 0x691D40)

PAGE_SIZE = 0x1000
INPUT_BASE = 0x50000000
THIS_BASE = 0x52000000
THIS_SIZE = 0x1000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x04000000
STACK_BASE = 0x70000000
STACK_SIZE = 0x00100000
RETURN_SENTINEL = 0x71000000
TEB_BASE = 0x72000000
GDT_BASE = 0x73000000
PROBE_OUT_BASE = 0x74000000


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & -alignment


def _make_gdt_entry(base: int, limit: int, access: int, flags: int) -> bytes:
    """构造一个 GDT 描述符（8 字节）。"""
    if limit > 0xFFFFF:
        limit >>= 12
        flags |= 0x8
    return struct.pack(
        "<IHHBB",
        base << 16 | (limit & 0xFFFF),
        (base >> 16) & 0xFFFF,
        1 | ((limit >> 16) & 0xF) | (flags << 4) | ((access & 0xFF) << 8) | 1 << 8,
        (base >> 24) & 0xFF,
        0,
    )[:8]


def setup_fs_segment(uc: Uc) -> None:
    """设置 FS 段指向 TEB 内存，让 fs:[0]（SEH 链）可读写。

    Unicorn 不自动处理段选择子，需要手动建 GDT 并设 GDTR + FS。
    """
    # TEB：fs:[0] = SEH 链头（设为 0xFFFFFFFF = 链末尾），fs:[4] 等随意。
    uc.mem_map(TEB_BASE, PAGE_SIZE)
    uc.mem_write(TEB_BASE, b"\xff\xff\xff\xff" + b"\0" * (PAGE_SIZE - 4))

    # GDT：entry 0=null, entry 1=FS 段（base=TEB_BASE, 粒度4K）
    uc.mem_map(GDT_BASE, PAGE_SIZE)
    gdt = bytearray(PAGE_SIZE)
    # entry 0: null
    # entry 1 (selector 0x1B = index 1, TI=0, RPL=3): data段, base=TEB_BASE
    # 描述符：base=TEB_BASE, limit=0xFFF, 粒度4K(实际 0xFFF*4K), data RW
    entry1 = bytearray(8)
    base = TEB_BASE
    limit = 0xFFF
    # access byte: P=1, DPL=3, S=1(data), type=3(RW) -> 0xF3
    access = 0xF3
    # flags: G=1, D/B=1 -> 0xC
    flags = 0xC
    struct.pack_into(
        "<I", entry1, 0,
        (base & 0xFFFF) | ((limit & 0xFFFF) << 16),
    )
    struct.pack_into(
        "<I", entry1, 4,
        ((base >> 16) & 0xFF)
        | ((access & 0xFF) << 8)
        | (((limit >> 16) & 0xF) << 16)
        | ((flags & 0xF) << 20)
        | (((base >> 24) & 0xFF) << 24),
    )
    gdt[8:16] = entry1
    uc.mem_write(GDT_BASE, bytes(gdt))

    # GDTR: base=GDT_BASE, limit=0xFFFF
    uc.reg_write(UC_X86_REG_GDTR, (0xFFFF, GDT_BASE, 0, 0))
    # Unicorn 不支持直接写段选择子。改用 FS_BASE 映射 + mem hook 兜底。
    # TEB 已经映射在 TEB_BASE，SEH 链头 fs:[0] = 0xFFFFFFFF（已写入）。
    # 由于 Unicorn 的 FS 段处理不完整，fs:[addr] 可能不走段映射，
    # 这里靠 mem_read_unmapped hook 把 fs 偏移访问重定向到 TEB_BASE。
    # 但 Unicorn 默认把 fs:[0] 当线性地址 0x0 访问，所以直接在地址 0 映射 TEB 副本。
    uc.mem_map(0x0, PAGE_SIZE)
    uc.mem_write(0x0, b"\xff\xff\xff\xff" + b"\0" * (PAGE_SIZE - 4))


def run(
    image_bytes: bytes,
    record_region: bytes,
    trace_decode: bool = False,
    post_parse_probe: str | None = None,
) -> dict:
    image = parse_image(image_bytes)
    image_base = image.image_base

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(image_base, align_up(image.image_size))
    uc.mem_write(image_base, image.data[: image.image_size])

    uc.mem_map(INPUT_BASE, max(PAGE_SIZE, align_up(len(record_region) + 64)))
    uc.mem_write(INPUT_BASE, record_region)
    uc.mem_map(THIS_BASE, THIS_SIZE)
    uc.mem_write(THIS_BASE, b"\0" * THIS_SIZE)
    uc.mem_map(HEAP_BASE, HEAP_SIZE)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(RETURN_SENTINEL, PAGE_SIZE)
    uc.mem_map(PROBE_OUT_BASE, PAGE_SIZE)

    setup_fs_segment(uc)

    # 初始化 __security_cookie（构造函数会读它做栈保护）
    uc.mem_write(SECURITY_COOKIE_VA, struct.pack("<I", 0xBB40E64E))

    heap_next = [HEAP_BASE]
    diag = {"errors": [], "trace": [], "memcpy_calls": []}

    # --- parse 分支硬断言：基于 image_base 构建观察/禁止地址集合 ---
    # forbidden：命中即证伪文档「esi==2」结论，立即 emu_stop。
    forbidden_va = {image_base + rva: rva for rva in FORBIDDEN_RVAS}
    # branch_watch：va -> 名称，命中即计数。用于事后判定走了哪条分支。
    branch_watch = {
        image_base + rva: name
        for rva, name in (
            (PARSE_DISPATCH_RVA, "dispatch"),
            (PARSE_CALL_ESI0_SITE, "esi0_call_site"),
            (PARSE_CALL_ESI1_SITE, "esi1_call_site"),
            (PARSE_CALL_ESI2_SITE, "esi2_call_site"),
            (ESI2_ENTRY_RVA, "esi2_entry"),
            (ESI2_CORE_RVA, "esi2_core"),
        )
    }
    read_eax_va = {image_base + rva for rva in PARSE_READ_EAX_AFTER_CLASSIFY}
    diag["classifier_results"] = []
    diag["dispatch_esi"] = None
    diag["branch_hits"] = {name: 0 for name in branch_watch.values()}
    diag["forbidden_hits"] = []

    # --- 0x136c080 字段类型分发插桩 ---
    # field_watch：字段解析器内 call site VA -> 名称，命中即计数。
    field_watch = {
        image_base + rva: name
        for rva, name in (
            (TYPE_READ_RVA, "type_read"),
            (MEMCPY_FIELD_CALLSITE, "memcpy_field"),
            (DECODER_T3_CALLSITE, "decoder_t3"),
            (DECODER_T56_CALLSITE, "decoder_t56"),
            (DECODER_T12_CALLSITE, "decoder_t12"),
        )
    }
    type_read_va = image_base + TYPE_READ_RVA
    diag["field_types"] = []          # [(type, stride1, stride2, datalen), ...]
    diag["type_counts"] = {0: 0, 1: 0, 2: 0, 3: 0, 5: 0, 6: 0, "other": 0}
    diag["memcpy_fields"] = []        # [(src, dst, len), ...]
    diag["decoder_hits"] = {"decoder_t3": 0, "decoder_t56": 0, "decoder_t12": 0}

    def return_from_call(return_value: int | None = None) -> None:
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack("<I", uc.mem_read(esp, 4))[0]
        if return_value is not None:
            uc.reg_write(UC_X86_REG_EAX, return_value)
        uc.reg_write(UC_X86_REG_ESP, esp + 4)
        uc.reg_write(UC_X86_REG_EIP, ret_addr)

    def code_hook(_uc, address, _size, _ud):
        nonlocal heap_next

        # --- 分支观察/禁止检查（先于 extern 桩，确保任何执行都可见）---
        if address in forbidden_va:
            # 命中 STEP2 声称的 esi==1 全链函数 -> 证伪当前样本走 esi==2 的结论
            diag["forbidden_hits"].append(forbidden_va[address])
            _uc.emu_stop()
            return
        name = branch_watch.get(address)
        if name is not None:
            diag["branch_hits"][name] += 1
            if name == "dispatch":
                # test esi,esi 处读 ESI = 最终分类结果（0/1/2）
                diag["dispatch_esi"] = _uc.reg_read(UC_X86_REG_ESI)
        elif address in read_eax_va:
            # mov esi,eax 处读 EAX = 分类器 0x136c430 的原始返回值
            diag["classifier_results"].append(_uc.reg_read(UC_X86_REG_EAX))

        # --- 0x136c080 字段类型分发观察 ---
        if address == type_read_va:
            # movzx eax,[esi] 处：esi 指向字段描述符，[esi+0]=type。
            esi = _uc.reg_read(UC_X86_REG_ESI)
            ftype = _uc.mem_read(esi, 1)[0]
            stride1, stride2, datalen = struct.unpack_from("<III", _uc.mem_read(esi + 0xC, 12))
            diag["field_types"].append((ftype, stride1, stride2, datalen))
            diag["type_counts"][ftype if ftype in (0, 1, 2, 3, 5, 6) else "other"] += 1
        else:
            fname = field_watch.get(address)
            if fname is not None:
                if fname == "memcpy_field":
                    # type==0 拷贝：EBX=src、EDX=len、[EBP+0x10]=dst。
                    ebp = _uc.reg_read(UC_X86_REG_EBP)
                    src = _uc.reg_read(UC_X86_REG_EBX)
                    datalen = _uc.reg_read(UC_X86_REG_EDX)
                    dst = struct.unpack("<I", _uc.mem_read(ebp + 0x10, 4))[0]
                    diag["memcpy_fields"].append((src, dst, datalen))
                elif fname in diag["decoder_hits"]:
                    # 非零 type 解码器命中：抓 src(EBX) / dst([ebp+0x10]) 作线索。
                    ebp = _uc.reg_read(UC_X86_REG_EBP)
                    src = _uc.reg_read(UC_X86_REG_EBX)
                    dst = struct.unpack("<I", _uc.mem_read(ebp + 0x10, 4))[0]
                    diag["decoder_hits"][fname] += 1
                    diag.setdefault("decoder_samples", []).append((fname, src, dst))

        esp = uc.reg_read(UC_X86_REG_ESP)
        if address == MALLOC_VA or address == OPERATOR_NEW_VA:
            size = struct.unpack("<I", _uc.mem_read(esp + 4, 4))[0]
            size = max(1, align_up(size, 16))
            allocation = heap_next[0]
            heap_next[0] += size
            if heap_next[0] > HEAP_BASE + HEAP_SIZE:
                raise MemoryError("emulated heap exhausted")
            return_from_call(allocation)
        elif address == FREE_VA:
            return_from_call()
        elif address == MEMCPY_VA or address == MEMCPY2_VA:
            # 两个 memcpy 副本同逻辑：0x136c080 type==0 走 MEMCPY2_VA。
            dst, src, count = struct.unpack("<III", _uc.mem_read(esp + 4, 12))
            diag["memcpy_calls"].append((address, src, dst, count))
            _uc.mem_write(dst, bytes(_uc.mem_read(src, count)))
            return_from_call(dst)
        elif address == MEMSET_VA:
            dst, val, count = struct.unpack("<III", _uc.mem_read(esp + 4, 12))
            _uc.mem_write(dst, bytes([val & 0xFF]) * count)
            return_from_call(dst)
        elif address == RETURN_SENTINEL:
            _uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, code_hook)

    # --- 第1步：跑构造函数 ---
    # 构造函数 __thiscall：ecx=this，ret 0x10（4 栈参数）
    # 参数内容未知，先传 0。构造函数主要做：基类构造 + 写虚表 + 成员初始化。
    sp = STACK_BASE + STACK_SIZE - 0x100
    uc.mem_write(
        sp,
        struct.pack(
            "<IIIII",
            RETURN_SENTINEL,  # return address
            INPUT_BASE,       # arg1（可能是数据指针）
            len(record_region),  # arg2
            0,                # arg3
            0,                # arg4
        ),
    )
    uc.reg_write(UC_X86_REG_ESP, sp)
    uc.reg_write(UC_X86_REG_ECX, THIS_BASE)
    uc.reg_write(UC_X86_REG_EIP, image_base + CTOR_RVA)

    try:
        uc.emu_start(image_base + CTOR_RVA, RETURN_SENTINEL + 1, timeout=15_000_000, count=10_000_000)
        diag["ctor_ok"] = True
    except Exception as exc:
        diag["ctor_ok"] = False
        diag["errors"].append(f"ctor error: {exc}")
        diag["errors"].append(f"EIP=0x{uc.reg_read(UC_X86_REG_EIP):#x}")

    # 读构造函数写入的对象头（虚表 + 成员）
    diag["this_head"] = bytes(uc.mem_read(THIS_BASE, 64)).hex(" ")
    diag["vtable_ptr"] = struct.unpack("<I", uc.mem_read(THIS_BASE, 4))[0]
    diag["heap_used"] = heap_next[0] - HEAP_BASE

    if not diag.get("ctor_ok"):
        return diag

    # --- 第2步：跑 parse ---
    # parse __thiscall：ecx=this，ret 0xc（3 栈参数）
    sp = STACK_BASE + STACK_SIZE - 0x100
    uc.mem_write(
        sp,
        struct.pack(
            "<IIII",
            RETURN_SENTINEL,
            INPUT_BASE,       # arg1：记录区/响应指针
            len(record_region),  # arg2
            0,                # arg3
        ),
    )
    uc.reg_write(UC_X86_REG_ESP, sp)
    uc.reg_write(UC_X86_REG_ECX, THIS_BASE)
    uc.reg_write(UC_X86_REG_EIP, image_base + PARSE_RVA)

    try:
        uc.emu_start(image_base + PARSE_RVA, RETURN_SENTINEL + 1, timeout=30_000_000, count=50_000_000)
        diag["parse_ok"] = True
    except Exception as exc:
        diag["parse_ok"] = False
        diag["errors"].append(f"parse error: {exc}")
        diag["errors"].append(f"EIP=0x{uc.reg_read(UC_X86_REG_EIP):#x}")

    diag["parse_eax"] = uc.reg_read(UC_X86_REG_EAX)
    diag["this_after_parse"] = bytes(uc.mem_read(THIS_BASE, 128)).hex(" ")
    diag["heap_used_after_parse"] = heap_next[0] - HEAP_BASE

    # 以实际 memcpy ABI 参数为准锁定 parse 搬入的最大数据块。call-site 寄存器只
    # 表示 0x136c080 的内部游标，不能可靠代表 memcpy(dst, src, len)。
    large_copies = [call for call in diag["memcpy_calls"] if call[3] >= 1024]
    if large_copies:
        _, src, dst, count = max(large_copies, key=lambda call: call[3])
        diag["record_buffer"] = (dst, count)
        diag["record_copy_source"] = src

    if post_parse_probe is not None and diag.get("parse_ok"):
        probe_rva = POST_PARSE_PROBES[post_parse_probe]
        raw_reads: dict[int, dict[str, int]] = {}
        record_buffer = diag.get("record_buffer")

        if record_buffer is not None:
            record_start, record_size = record_buffer

            def record_read_hook(_uc, _access, address, size, _value, _ud):
                eip = _uc.reg_read(UC_X86_REG_EIP)
                hit = raw_reads.setdefault(
                    eip,
                    {"count": 0, "bytes": 0, "first_address": address, "max_size": size},
                )
                hit["count"] += 1
                hit["bytes"] += size
                hit["max_size"] = max(hit["max_size"], size)

            uc.hook_add(
                UC_HOOK_MEM_READ,
                record_read_hook,
                begin=record_start,
                end=record_start + record_size - 1,
            )

        uc.mem_write(PROBE_OUT_BASE, b"\0" * PAGE_SIZE)
        sp = STACK_BASE + STACK_SIZE - 0x100
        uc.mem_write(
            sp,
            struct.pack(
                "<III",
                RETURN_SENTINEL,
                THIS_BASE,
                PROBE_OUT_BASE,
            ),
        )
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EIP, image_base + probe_rva)

        probe_diag = {
            "name": post_parse_probe,
            "rva": probe_rva,
            "record_buffer": record_buffer,
            "ok": False,
        }
        try:
            uc.emu_start(
                image_base + probe_rva,
                RETURN_SENTINEL + 1,
                timeout=30_000_000,
                count=50_000_000,
            )
            probe_diag["ok"] = True
        except Exception as exc:
            probe_diag["error"] = str(exc)
            probe_diag["error_eip"] = uc.reg_read(UC_X86_REG_EIP)
            diag["errors"].append(
                f"post-parse probe {post_parse_probe} error: {exc}; "
                f"EIP=0x{probe_diag['error_eip']:08x}"
            )
        probe_diag["eax"] = uc.reg_read(UC_X86_REG_EAX)
        probe_diag["out_count"] = struct.unpack(
            "<I", uc.mem_read(PROBE_OUT_BASE, 4)
        )[0]
        probe_diag["raw_read_sites"] = [
            (eip, values)
            for eip, values in sorted(
                raw_reads.items(),
                key=lambda item: (-item[1]["count"], item[0]),
            )
        ]
        probe_diag["raw_read_total"] = sum(
            values["count"] for values in raw_reads.values()
        )
        diag["post_parse_probe"] = probe_diag

    diag["_uc"] = uc
    diag["_heap_next"] = heap_next[0]

    # --- 分支硬断言判定（文档 CORRECTION §四：当前 flag=0x0082 样本应走 esi==2）---
    hits = diag["branch_hits"]
    diag["branch_ok"] = (
        diag["dispatch_esi"] == 2
        and hits.get("esi2_call_site", 0) >= 1
        and hits.get("esi2_entry", 0) >= 1
        and hits.get("esi2_core", 0) >= 1
        and hits.get("esi1_call_site", 0) == 0
        and hits.get("esi0_call_site", 0) == 0
        and not diag["forbidden_hits"]
    )
    return diag


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", type=Path, default=Path("captures_live/hexin.loaded.bin"))
    ap.add_argument(
        "--record",
        type=Path,
        default=Path("tests/fixtures/history_timeline/_tmp_000001_subtable.bin"),
    )
    ap.add_argument(
        "--post-parse-probe",
        choices=tuple(POST_PARSE_PROBES),
        help="parse 成功后主动调用真实上层 helper，并监控其对记录缓冲的读取",
    )
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    region = args.record.read_bytes()
    print(f"record region: {len(region)}B, head: {region[:16].hex(' ')}")

    diag = run(
        args.image.read_bytes(),
        region,
        post_parse_probe=args.post_parse_probe,
    )
    print(f"ctor_ok: {diag.get('ctor_ok')}")
    print(f"vtable_ptr: 0x{diag.get('vtable_ptr', 0):#x} (expect 0x281b2bc)")
    print(f"this_head: {diag.get('this_head')}")
    print(f"heap_used: {diag.get('heap_used')}")
    print(f"parse_ok: {diag.get('parse_ok')}")
    print(f"parse_eax: 0x{diag.get('parse_eax', 0):#x}")
    print(f"this_after_parse: {diag.get('this_after_parse')}")
    print(f"heap_used_after_parse: {diag.get('heap_used_after_parse')}")
    record_buffer = diag.get("record_buffer")
    if record_buffer is not None:
        print(
            f"record_buffer: dst=0x{record_buffer[0]:08x} len={record_buffer[1]} "
            f"src=0x{diag.get('record_copy_source', 0):08x}"
        )
    # --- 分支证据链 ---
    print(f"classifier_results: {diag.get('classifier_results')}")
    print(f"dispatch_esi: {diag.get('dispatch_esi')} (expect 2)")
    print(f"branch_hits: {diag.get('branch_hits')}")
    print(f"forbidden_hits: {[hex(r) for r in diag.get('forbidden_hits', [])]}")
    print(f"branch_ok: {diag.get('branch_ok')}")
    # --- 0x136c080 字段类型分发证据 ---
    print(f"field_type_total: {len(diag.get('field_types', []))}")
    print(f"type_counts: {diag.get('type_counts')}")
    print(f"decoder_hits: {diag.get('decoder_hits')}")
    mf = diag.get("memcpy_fields", [])
    print(f"memcpy_fields_count: {len(mf)}")
    for src, dst, n in mf[:10]:
        print(f"  memcpy src=0x{src:08x} dst=0x{dst:08x} len={n}")
    ds = diag.get("decoder_samples", [])
    for name, src, dst in ds[:10]:
        print(f"  decoder {name} src=0x{src:08x} dst=0x{dst:08x}")
    nonzero = sum(v for k, v in diag.get("decoder_hits", {}).items() if v)
    if nonzero:
        print("判定: 发现非 memcpy 解码路径 (type1/2/3/5/6)，消费者候选见 decoder_hits")
    else:
        print("判定: 全部 type==0 memcpy；parse 内无字段级解码")
    probe = diag.get("post_parse_probe")
    if probe is not None:
        print(
            f"post_parse_probe: {probe['name']} ok={probe['ok']} "
            f"eax=0x{probe['eax']:08x} out_count={probe['out_count']} "
            f"raw_read_total={probe['raw_read_total']}"
        )
        for eip, values in probe["raw_read_sites"][:20]:
            print(
                f"  raw-read eip=0x{eip:08x} count={values['count']} "
                f"bytes={values['bytes']} first=0x{values['first_address']:08x} "
                f"max_size={values['max_size']}"
            )
    for err in diag["errors"]:
        print(f"ERROR: {err}")
    # branch_ok 为 False 时返回非零，便于 CI/脚本判定分支结论是否成立。
    if not diag.get("branch_ok"):
        return 2
    if args.post_parse_probe and not diag.get("post_parse_probe", {}).get("ok"):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
