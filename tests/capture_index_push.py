#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""抓取并分析同花顺 PC 客户端的指数实时推送。

目标
----
1. 找到打开指数分时页时客户端发出的 8901 订阅/查询帧；
2. 找到同一 TCP 流上的 ``CodeListSize`` 注册回执；
3. 证明客户端静默后服务器仍持续下发指数快照，并解出 OHLC/最新点位。

推荐用法（必须在交易时段观察实时推送）::

    uv run python tests/capture_index_push.py --duration 120
    uv run python tests/capture_index_push.py --iface 4 --duration 90
    uv run python tests/capture_index_push.py --analyze-only captures_live/xxx.pcap

抓包期间的操作顺序：

* 前 10 秒保持客户端不动，采集基线；
* 打开上证指数（1A0001）分时页，停留 20~30 秒；
* 打开深证成指（399001）分时页，停留 20~30 秒；
* 页面停住，不滚动、不切周期，让服务端主动推送更容易辨认。

产物为原始 pcap、文本分析报告和逐帧 JSONL。JSONL 保留完整 body_hex，
便于后续对 301B/320B 帧继续做字段差分。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.protocol import decode_ths_float  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass


PORT = 8901
MAGIC = b"\xfd\xfd\xfd\xfd"
CAPTURE_DIR = ROOT / "captures_live"
DEFAULT_CODES = ("1A0001", "399001")
MAX_FRAME_SIZE = 32 * 1024 * 1024

WIRESHARK_DIRS = (
    Path(r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"),
    Path(r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"),
    Path(r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark"),
    Path(r"C:\Program Files\Wireshark"),
    Path(r"D:\Program Files\Wireshark"),
)

# A 股主要指数、北交所指数和同花顺行业/概念指数。
INDEX_CODE_TEXT_RE = re.compile(
    r"^(?:1[AB][0-9A-Z]{4}|399\d{3}|899\d{3}|88[15]\d{3})$",
    re.IGNORECASE,
)
INDEX_CODE_BYTES_RE = re.compile(
    rb"(?:1[AB][0-9A-Z]{4}|399\d{3}|899\d{3}|88[15]\d{3})",
    re.IGNORECASE,
)


@dataclass(slots=True)
class FrameEvent:
    time: float
    stream: int
    direction: str
    body: bytes


def _find_tool(name: str) -> Path:
    for directory in WIRESHARK_DIRS:
        candidate = directory / f"{name}.exe"
        if candidate.is_file():
            return candidate
    found = shutil.which(name) or shutil.which(f"{name}.exe")
    if found:
        return Path(found)
    tried = "\n  ".join(str(p / f"{name}.exe") for p in WIRESHARK_DIRS)
    raise FileNotFoundError(f"找不到 {name}.exe，已检查：\n  {tried}")


def _run_tool(args: list[str], timeout: int = 180) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise RuntimeError(f"命令失败 ({result.returncode}): {' '.join(args[:3])}\n{detail}")
    return result


def list_interfaces(tshark: Path) -> dict[str, tuple[str, str]]:
    result = _run_tool([str(tshark), "-D"], timeout=20)
    text = result.stdout.decode("gbk", "replace")
    interfaces: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        match = re.match(r"(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line)
        if match:
            interfaces[match.group(1)] = (
                match.group(2),
                (match.group(3) or match.group(2)).strip(),
            )
    return interfaces


def pick_interface(tshark: Path, requested: str | None) -> str:
    interfaces = list_interfaces(tshark)
    if not interfaces:
        raise RuntimeError("tshark 没有返回可用网卡；请检查 Npcap 是否安装")
    if requested:
        if requested not in interfaces:
            known = ", ".join(f"{n}={v[1]}" for n, v in interfaces.items())
            raise ValueError(f"网卡编号 {requested!r} 不存在；当前网卡：{known}")
        return requested

    print("网卡列表：")
    for number, (_, description) in interfaces.items():
        preferred = any(key in description.lower() for key in ("wlan", "wi-fi", "wifi"))
        print(f"  {number}. {description}{'  ← 建议' if preferred else ''}")
    default = next(
        (
            number
            for number, (_, description) in interfaces.items()
            if any(key in description.lower() for key in ("wlan", "wi-fi", "wifi"))
        ),
        next(iter(interfaces)),
    )
    choice = input(f"选择网卡编号 [{default}]: ").strip() or default
    if choice not in interfaces:
        raise ValueError(f"网卡编号 {choice!r} 不存在")
    return choice


def capture(dumpcap: Path, interface: str, duration: int, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        str(dumpcap),
        "-i",
        interface,
        "-f",
        f"tcp port {PORT}",
        "-w",
        str(output),
        "-a",
        f"duration:{duration}",
    ]
    print("\n开始抓指数推送：")
    print("  0~10s   客户端保持不动")
    print("  10~40s  打开上证指数分时页并保持不动")
    print("  40~70s  打开深证成指分时页并保持不动")
    print("  其余时间 可切换其他指数，每次至少停留 20 秒")
    print(f"\n抓包 {duration}s，输出 {output}")
    try:
        result = subprocess.run(command, timeout=duration + 20)
    except KeyboardInterrupt:
        print("\n收到 Ctrl+C；dumpcap 会保留已经写入的包。")
        return
    except subprocess.TimeoutExpired:
        print("dumpcap 已到达外层超时；继续分析已保存的数据。")
        return
    if result.returncode:
        raise RuntimeError(f"dumpcap 退出码 {result.returncode}，请检查管理员权限和网卡编号")
    size = output.stat().st_size if output.exists() else 0
    print(f"抓包完成：{output} ({size:,} bytes)")


def _packet_rows(tshark: Path, pcap: Path) -> list[tuple[float, int, int, int, bytes]]:
    display_filter = (
        f"tcp.port=={PORT} and tcp.payload and "
        "not tcp.analysis.retransmission and "
        "not tcp.analysis.fast_retransmission and "
        "not tcp.analysis.spurious_retransmission"
    )
    result = _run_tool(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.time_relative",
            "-e",
            "tcp.stream",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.payload",
        ],
        timeout=240,
    )
    rows: list[tuple[float, int, int, int, bytes]] = []
    for raw_line in result.stdout.splitlines():
        parts = raw_line.split(b"\t", 4)
        if len(parts) != 5:
            continue
        try:
            payload_hex = re.sub(rb"[^0-9A-Fa-f]", b"", parts[4])
            if not payload_hex:
                continue
            rows.append(
                (
                    float(parts[0]),
                    int(parts[1]),
                    int(parts[2]),
                    int(parts[3]),
                    bytes.fromhex(payload_hex.decode("ascii")),
                )
            )
        except (ValueError, IndexError):
            continue
    return rows


def _take_frames(buffer: bytearray) -> list[bytes]:
    """从一个方向的 TCP 字节流中取出完整 FDF 帧，残帧留在 buffer。"""
    frames: list[bytes] = []
    while True:
        start = buffer.find(MAGIC)
        if start < 0:
            if len(buffer) > len(MAGIC) - 1:
                del buffer[: -(len(MAGIC) - 1)]
            return frames
        if start:
            del buffer[:start]
        if len(buffer) < 12:
            return frames

        # 行情服务器偶发五个或更多连续 0xfd，长度字段从最后一个 fd 后开始。
        length_start = 4
        while length_start < len(buffer) and buffer[length_start] == 0xFD:
            length_start += 1
        if len(buffer) < length_start + 8:
            return frames
        length_raw = bytes(buffer[length_start : length_start + 8])
        if not re.fullmatch(rb"[0-9A-Fa-f]{8}", length_raw):
            del buffer[0]
            continue
        body_size = int(length_raw, 16)
        if body_size > MAX_FRAME_SIZE:
            del buffer[0]
            continue
        end = length_start + 8 + body_size
        if len(buffer) < end:
            return frames
        frames.append(bytes(buffer[length_start + 8 : end]))
        del buffer[:end]


def reconstruct_frames(rows: list[tuple[float, int, int, int, bytes]]) -> list[FrameEvent]:
    buffers: dict[tuple[int, str], bytearray] = defaultdict(bytearray)
    events: list[FrameEvent] = []
    for timestamp, stream, source, destination, payload in rows:
        direction = "S2C" if source == PORT else "C2S" if destination == PORT else "?"
        if direction == "?":
            continue
        buffer = buffers[(stream, direction)]
        buffer.extend(payload)
        for body in _take_frames(buffer):
            events.append(FrameEvent(timestamp, stream, direction, body))
    return sorted(events, key=lambda event: (event.time, event.stream))


def _is_index_code(code: str) -> bool:
    return bool(INDEX_CODE_TEXT_RE.fullmatch(code.strip()))


def _codes_in_body(body: bytes) -> list[str]:
    return list(
        dict.fromkeys(match.group().decode("ascii").upper() for match in INDEX_CODE_BYTES_RE.finditer(body))
    )


def _request_info(event: FrameEvent) -> dict[str, object] | None:
    text = event.body.decode("gbk", "replace")
    code_groups = re.findall(r"CodeList=(\d+)\(([^)]*)\)", text, re.IGNORECASE)
    codes: list[str] = []
    markets: list[int] = []
    for market, group in code_groups:
        group_codes = [part.strip() for part in group.split(",") if part.strip()]
        index_codes = [code.upper() for code in group_codes if _is_index_code(code)]
        if index_codes:
            markets.append(int(market))
            codes.extend(index_codes)
    if not codes:
        return None

    def values(pattern: str) -> list[str]:
        return list(dict.fromkeys(re.findall(pattern, text, re.IGNORECASE)))

    datatypes = values(r"DataType=([^\r\n]+)")
    datetime_values = values(r"DateTime=([^\r\n]+)")
    push_fields = values(r"PushField=([^\r\n]+)")
    methods = values(r"method=([\w-]+)")
    actions = values(r"action=([\w-]+)")
    pageids = [int(value) for value in values(r"pageid=(\d+)")]
    if push_fields and 5716 in pageids:
        kind = "5716 指数推送订阅"
    elif 4214 in pageids:
        kind = "4214 快照订阅"
    elif any(value.startswith("8192(") for value in datetime_values):
        kind = "分时查询"
    elif methods:
        kind = "/".join(methods)
    else:
        kind = "指数请求"
    return {
        "time": event.time,
        "stream": event.stream,
        "kind": kind,
        "markets": list(dict.fromkeys(markets)),
        "codes": list(dict.fromkeys(codes)),
        "pageids": pageids,
        "datatypes": datatypes,
        "datetimes": datetime_values,
        "push_fields": push_fields,
        "methods": methods,
        "actions": actions,
        "body_size": len(event.body),
    }


def _decode_ohlc(body: bytes, code: str) -> dict[str, float] | None:
    """解出标准指数快照中的昨收、开、高、低、最新。

    沪指五字段紧跟代码 6B；深指代码之后还有 26B 壳。这里使用相对代码
    位置，而不是固定帧偏移，从而兼容 ``状态文本 + 399006 快照`` 这类 487B
    复合帧。
    """
    code_position = body.find(code.encode("ascii"))
    if code_position < 0:
        return None
    offset = (
        code_position + 6
        if code.startswith(("1A", "1B"))
        else code_position + 26
        if code.startswith("399")
        else None
    )
    if offset is None or len(body) < offset + 20:
        return None
    values = [decode_ths_float(struct.unpack_from("<I", body, offset + i * 4)[0]) for i in range(5)]
    if not all(0 < value < 10_000_000 for value in values):
        return None
    return dict(zip(("prev_close", "open", "high", "low", "latest"), values))


def _decode_bj50_compact(body: bytes, code: str) -> dict[str, float] | None:
    """解出 899050 的 97/98B 稳态紧凑帧已确认字段。

    字段由同机 ``pageid=9354`` 分时响应逐字节标定。93B 省略型帧的字段
    掩码不同，不在这里用固定偏移强解。
    """
    code_position = body.find(code.encode("ascii"))
    if code_position < 0 or len(body) not in (97, 98):
        return None
    offsets = {
        "latest": code_position + 6,
        "volume": code_position + 10,
        "amount": code_position + 14,
        "dt22": code_position + 30,
        "dt23": code_position + 34,
    }
    if max(offsets.values()) + 4 > len(body):
        return None
    decoded = {
        name: decode_ths_float(struct.unpack_from("<I", body, offset)[0])
        for name, offset in offsets.items()
    }
    if not 500 < decoded["latest"] < 5_000:
        return None
    return decoded


def _push_info(event: FrameEvent) -> dict[str, object] | None:
    if event.direction != "S2C" or not 80 <= len(event.body) <= 900:
        return None
    codes = _codes_in_body(event.body)
    if not codes:
        return None
    # 排除带 CodeList 文本的请求回显/回执；指数快照本身含裸 ASCII 代码。
    if b"CodeList=" in event.body or b"CodeListSize=" in event.body:
        return None
    code = codes[0]
    ohlc = _decode_ohlc(event.body, code)
    compact = code.startswith("899") and 80 <= len(event.body) <= 140
    compact_fields = _decode_bj50_compact(event.body, code) if compact else None
    if ohlc is None and not compact:
        return None
    return {
        "time": event.time,
        "stream": event.stream,
        "code": code,
        "body_size": len(event.body),
        "ohlc": ohlc,
        "compact_fields": compact_fields,
        "layout": "compact" if compact else "standard",
        "sha256": hashlib.sha256(event.body).hexdigest(),
        "head_hex": event.body[:48].hex(),
    }


def analyze(tshark: Path, pcap: Path, report_path: Path | None = None) -> dict[str, object]:
    if not pcap.is_file():
        raise FileNotFoundError(f"pcap 不存在：{pcap}")
    rows = _packet_rows(tshark, pcap)
    events = reconstruct_frames(rows)
    requests = [info for event in events if event.direction == "C2S" if (info := _request_info(event))]
    replies = []
    pushes = []
    push_bodies: list[tuple[dict[str, object], bytes]] = []
    for event in events:
        if event.direction != "S2C":
            continue
        size_matches = re.findall(rb"CodeListSize=(\d+)", event.body)
        if size_matches:
            sizes = [int(value) for value in size_matches]
            replies.append(
                {
                    "time": event.time,
                    "stream": event.stream,
                    "code_list_size": max(sizes),
                    "code_list_sizes": sizes,
                    "body_size": len(event.body),
                }
            )
        info = _push_info(event)
        if info:
            pushes.append(info)
            push_bodies.append((info, event.body))

    print(f"\n{'=' * 72}")
    print(f"指数实时推送分析：{pcap}")
    print(f"{'=' * 72}")
    print(f"TCP payload 包 {len(rows)} 个，重组 FDF 帧 {len(events)} 个，TCP 流 {len({e.stream for e in events})} 条")

    print("\n[1] 指数请求/订阅时间线")
    if not requests:
        print("  未发现带指数 CodeList 的请求；若后面存在快照，说明订阅动作早于本次抓包。")
    request_groups: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for item in requests:
        key = (
            item["stream"],
            item["kind"],
            tuple(item["markets"]),
            tuple(item["codes"]),
            tuple(item["pageids"]),
            tuple(item["datatypes"]),
            tuple(item["datetimes"]),
            tuple(item["push_fields"]),
        )
        request_groups[key].append(item)
    # 优先显示明确的 4214 订阅和 8192 分时请求，再显示首次出现的启动请求。
    ordered_request_groups = sorted(
        request_groups.values(),
        key=lambda items: (
            0 if 4214 in items[0]["pageids"] else 1,
            0 if items[0]["kind"] == "分时查询" else 1,
            items[0]["time"],
        ),
    )
    for items in ordered_request_groups[:30]:
        item = items[0]
        dtype = "; ".join(item["datatypes"]) or "-"
        if len(dtype) > 88:
            dtype = dtype[:85] + "..."
        repeat = f" ×{len(items)}" if len(items) > 1 else ""
        print(
            f"  {item['time']:8.3f}s stream={item['stream']:<3} {item['kind']:<14} "
            f"market={item['markets']} code={','.join(item['codes'])} pageid={item['pageids']}{repeat}"
        )
        print(f"             DataType={dtype} DateTime={item['datetimes'] or '-'}")
        if item["push_fields"]:
            print(f"             PushField={item['push_fields']}")
    if len(ordered_request_groups) > 30:
        print(f"  ... 另有 {len(ordered_request_groups) - 30} 种启动/辅助请求，完整内容见 JSON 报告。")

    print("\n[2] 注册回执")
    relevant_streams = {int(item["stream"]) for item in requests}
    subscription_requests = [
        item
        for item in requests
        if 4214 in item["pageids"] or bool(item["push_fields"])
    ]
    relevant_replies = [
        reply
        for reply in replies
        if any(
            reply["stream"] == request["stream"]
            and request["time"] <= reply["time"] <= request["time"] + 0.5
            for request in subscription_requests
        )
        and reply["code_list_size"] > 0
    ]
    if not relevant_replies:
        if subscription_requests:
            print("  未发现指数订阅后 0.5 秒内的非零 CodeListSize 回执。")
        else:
            print("  本包未发现显式 pageid=4214 订阅，因此不把启动期的大量 CodeListSize 当成订阅回执。")
    for reply in relevant_replies:
        print(
            f"  {reply['time']:8.3f}s stream={reply['stream']:<3} "
            f"CodeListSize={reply['code_list_sizes']} ({reply['body_size']}B)"
        )

    print("\n[3] 服务端指数快照候选")
    # 抓包常从已登录、已订阅的长连接中途开始；此时没有 C2S CodeList，不能
    # 因此丢弃随后真实到达的 S2C 指数帧。
    relevant_pushes = (
        [push for push in pushes if push["stream"] in relevant_streams]
        if relevant_streams
        else pushes
    )
    if not relevant_pushes:
        print("  未发现指数快照。非交易时段通常不会持续推送。")
    grouped: dict[tuple[int, str, int], list[dict[str, object]]] = defaultdict(list)
    for push in relevant_pushes:
        grouped[(int(push["stream"]), str(push["code"]), int(push["body_size"]))].append(push)
    for (stream, code, size), items in sorted(grouped.items(), key=lambda pair: pair[1][0]["time"]):
        times = [float(item["time"]) for item in items]
        intervals = [right - left for left, right in zip(times, times[1:])]
        interval_text = f"，间隔中位附近={sorted(intervals)[len(intervals) // 2]:.3f}s" if intervals else ""
        same_code_requests = [
            request
            for request in requests
            if request["stream"] == stream
            and code in request["codes"]
            and times[0] <= request["time"] <= times[-1]
        ]
        request_text = f"，期间同码请求={len(same_code_requests)}"
        print(
            f"  stream={stream:<3} code={code} {size}B × {len(items)}，"
            f"{times[0]:.3f}s → {times[-1]:.3f}s{interval_text}{request_text}"
        )
        for item in items[:5]:
            ohlc = item["ohlc"]
            if ohlc:
                print(
                    f"    {item['time']:8.3f}s 昨={ohlc['prev_close']:.6g} "
                    f"开={ohlc['open']:.6g} 高={ohlc['high']:.6g} "
                    f"低={ohlc['low']:.6g} 最新={ohlc['latest']:.6g}"
                )
            elif item["compact_fields"]:
                fields = item["compact_fields"]
                print(
                    f"    {item['time']:8.3f}s 最新={fields['latest']:.6g} "
                    f"量={fields['volume']:.6g} 额={fields['amount']:.6g} "
                    f"dt22={fields['dt22']:.6g} dt23={fields['dt23']:.6g}"
                )
            else:
                print(f"    {item['time']:8.3f}s head={item['head_hex'][:64]}")

    print("\n[4] 结论")
    repeated = []
    for (stream, code, _), items in grouped.items():
        same_code_request_count = sum(
            1
            for request in requests
            if request["stream"] == stream
            and code in request["codes"]
            and items[0]["time"] <= request["time"] <= items[-1]["time"]
        )
        if (
            len(items) >= 2
            and items[-1]["time"] > items[0]["time"]
            and len(items) > same_code_request_count + 1
        ):
            repeated.append(items)
    if repeated:
        print("  同码服务端快照数显著多于客户端同码请求数：这是持续推送，不是逐次轮询响应。")
        if any(4214 in item["pageids"] for item in requests):
            print("  链路为：8901 / pageid=4214 CodeList 订阅 → CodeListSize 回执 → 指数快照持续下发。")
        elif any(item["push_fields"] for item in requests):
            print("  链路为：8901 subreal 五通道 + pageid=5716/PushField CodeList → CodeListSize → 指数快照。")
        else:
            if requests:
                print("  本包没有显式 4214；推送已在启动连接上激活，需结合启动 CodeList/pageid=5716 序列继续定位注册帧。")
            else:
                print("  抓包从已建立的行情连接中途开始，订阅动作早于本包；本包只能证明推送形态和节奏。")
    elif relevant_pushes:
        print("  已抓到指数快照，但每组只有 1 帧；建议盘中停留页面 20 秒以上重抓。")
        if any(item["push_fields"] for item in requests):
            print("  冷启动订阅链已完整出现：subreal 五通道 + pageid=5716/PushField → CodeListSize → 首批快照。")
    else:
        print("  本包不足以证明持续推送；请在交易时段按脚本提示重抓。")

    report = {
        "pcap": str(pcap.resolve()),
        "packet_count": len(rows),
        "frame_count": len(events),
        "stream_count": len({event.stream for event in events}),
        "requests": requests,
        "registration_replies": relevant_replies,
        "pushes": relevant_pushes,
        "push_groups": [
            {
                "stream": stream,
                "code": code,
                "body_size": size,
                "count": len(items),
                "first_time": items[0]["time"],
                "last_time": items[-1]["time"],
            }
            for (stream, code, size), items in grouped.items()
        ],
    }
    report_path = report_path or pcap.with_name(f"{pcap.stem}_index_push_report.json")
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    jsonl_path = report_path.with_name(f"{report_path.stem.removesuffix('_report')}_frames.jsonl")
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for info, body in push_bodies:
            if info not in relevant_pushes:
                continue
            handle.write(json.dumps({**info, "body_hex": body.hex()}, ensure_ascii=False) + "\n")
    print(f"\n报告：{report_path}")
    print(f"原始推送帧：{jsonl_path}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="抓取并分析同花顺 PC 指数实时推送")
    parser.add_argument("--duration", type=int, default=120, help="抓包秒数，默认 120")
    parser.add_argument("--iface", help="dumpcap 网卡编号；不传则交互选择")
    parser.add_argument("--analyze-only", type=Path, help="只分析已有 pcap/pcapng")
    parser.add_argument("--output", type=Path, help="抓包输出路径")
    parser.add_argument("--report", type=Path, help="JSON 报告输出路径")
    args = parser.parse_args()

    try:
        tshark = _find_tool("tshark")
        if args.analyze_only:
            analyze(tshark, args.analyze_only.resolve(), args.report)
            return 0
        if args.duration < 15:
            parser.error("--duration 至少 15 秒")
        dumpcap = _find_tool("dumpcap")
        interface = pick_interface(tshark, args.iface)
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output = (args.output or CAPTURE_DIR / f"index_push_{stamp}.pcapng").resolve()
        capture(dumpcap, interface, args.duration, output)
        analyze(tshark, output, args.report)
        return 0
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
