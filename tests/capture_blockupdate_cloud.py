#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺板块云同步 (BlockUpdate / cloud.10jqka.com.cn:443) 的 HTTPS 明文。

组合三件套:
  1. Frida hook wininet.dll 的 6 个关键 API,还原请求/响应明文(可读,绕过 TLS)
  2. 监控本地 BlockUpdate/__base_/_entries 的 version/CRC/last_* 变化
  3. (可选) dumpcap 抓 cloud.10jqka.com.cn:443 的 TLS 流量作时序参照

详见 docs/handoffs/HANDOFF_BLOCKUPDATE_CLOUD_SYNC_20260810.md 的 P0。

用法
----
    # 推荐:frida + 文件监控(够用,且能拿到明文)
    py tests/capture_blockupdate_cloud.py --no-dumpcap

    # 全套:frida + 文件监控 + dumpcap
    py tests/capture_blockupdate_cloud.py --duration 600

    # 只想看明文,不想 spawn 同花顺(手动开)
    py tests/capture_blockupdate_cloud.py --attach hexin.exe

    # 让脚本帮你 spawn 同花顺(默认,推荐)
    py tests/capture_blockupdate_cloud.py --spawn

操作步骤
--------
    1. 确保同花顺**已退出**(任务管理器确认无 hexin.exe)
    2. 运行本脚本(默认会 spawn 同花顺并 attach)
    3. 等待 hook ready 后,在 GUI 里正常登录
    4. 登录后会触发板块云同步;盯 stdout 看 cloud.10jqka.com.cn 的请求
    5. _entries 变化时脚本会高亮打印;Ctrl+C 或等 duration 结束
    6. 产物在 captures_live/blockupdate_<时间戳>/

产物
----
    blockupdate_<ts>/
      frida_log.jsonl   # 全部 hook message,带时间戳
      frida_summary.txt  # 按 request 事务归并的明文摘要
      entries_before.txt / entries_after.txt
      changed_files/    # 发生变化的 .ini 文件前后对比(若有)
      *.pcap            # dumpcap(若启用)
"""
from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

import _blockupdate_lib as bl  # noqa: E402

# ── 路径 ───────────────────────────────────────────────────────
DUMPCAP = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\dumpcap.exe"
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
HOOK_JS = pathlib.Path(__file__).with_name("_blockupdate_frida_hook.js")
CAPTURES_DIR = ROOT / "captures_live"

# 同花顺可执行(交接文档路径)
HEXIN_EXE = r"C:\同花顺软件\同花顺\hexin.exe"

# 关注的目标主机(只高亮这些;其它 WinINet 流量也记,但低优先级)
TARGET_HOSTS = ("cloud.10jqka.com.cn",)


def now_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


# ── dumpcap ────────────────────────────────────────────────────
def list_ifaces() -> dict[str, str]:
    r = subprocess.run([TSHARK, "-D"], capture_output=True,
                       encoding="gbk", errors="replace", timeout=15)
    out: dict[str, str] = {}
    for ln in (r.stdout or "").splitlines():
        m = re.match(r"(\d+)\.\s+(\S+)\s+\((.+?)\)", ln)
        if m:
            out[m.group(1)] = m.group(3)
    return out


def pick_iface(default: str | None = None) -> str:
    ifaces = list_ifaces()
    if not ifaces:
        print("✗ 未检测到网卡,dumpcap 不可用")
        sys.exit(1)
    print("网卡列表:")
    for num, desc in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    if default is None:
        default = next((n for n, d in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
    if choice not in ifaces:
        print("无效编号,用默认")
        choice = default
    return choice


def start_dumpcap(out_pcap: pathlib.Path, iface: str, duration: int) -> subprocess.Popen | None:
    """dumpcap 只抓 cloud.10jqka.com.cn:443(BPF 过滤)。"""
    if not pathlib.Path(DUMPCAP).exists():
        print(f"✗ dumpcap 不存在: {DUMPCAP}")
        return None
    cmd = [
        DUMPCAP, "-i", iface, "-q",
        "-f", "host cloud.10jqka.com.cn and tcp port 443",
        "-w", str(out_pcap),
    ]
    # dumpcap 没有 -a duration 时,用 -a duration:N
    cmd += ["-a", f"duration:{duration}"]
    print(f"  dumpcap: {' '.join(cmd)}")
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


# ── frida ──────────────────────────────────────────────────────
def make_frida_session(spawn: bool, attach: str | None, exe: str):
    """返回 (session, pid)。spawn=True 则启动 exe 并 attach。"""
    import frida

    dev = frida.get_local_device()

    if spawn:
        if not pathlib.Path(exe).exists():
            raise FileNotFoundError(f"同花顺可执行不存在: {exe}")
        print(f"  frida spawn: {exe}")
        pid = dev.spawn([exe])
        session = dev.attach(pid)
        return session, pid, dev

    # attach 到已运行的进程
    target = attach or "hexin.exe"
    # 模糊匹配进程名
    found = None
    for p in dev.enumerate_processes():
        if p.name.lower() == target.lower():
            found = p.pid
            break
    if found is None:
        # 部分匹配
        for p in dev.enumerate_processes():
            if target.lower() in p.name.lower():
                found = p.pid
                break
    if found is None:
        raise RuntimeError(f"找不到进程 {target},请先启动同花顺或用 --spawn")
    print(f"  frida attach pid={found} ({target})")
    session = dev.attach(found)
    return session, found, dev


# ── hook message 处理 ──────────────────────────────────────────
class HookCollector:
    """收集 frida message,按 request handle 归并事务,实时高亮目标主机请求。

    响应/请求体字节用 frida 的 data 附件通道传输(on_message 第二参数),
    不经 JSON 序列化,不会丢。每个事务的 body 写成单独 .bin 便于离线分析。
    """

    def __init__(self, log_file: pathlib.Path, bodies_dir: pathlib.Path):
        self.log_path = log_file
        self.bodies_dir = bodies_dir
        self.bodies_dir.mkdir(parents=True, exist_ok=True)
        self.log_fh = log_file.open("w", encoding="utf-8")
        self.lock = threading.Lock()
        # handle -> tx 状态
        self.tx: dict[str, dict] = defaultdict(dict)
        # conn handle -> {server, port}
        self.conn: dict[str, dict] = {}
        # 请求事务列表(handle, server, verb, obj)
        self.request_handles: list[str] = []
        # body 分片文件:handle -> list[(offset, path)]
        self.body_files: dict[str, list] = defaultdict(list)
        self._body_offset: dict[str, int] = defaultdict(int)

    def close(self):
        self.log_fh.close()

    def on_message(self, message, data):
        ts = now_str()
        if message["type"] == "error":
            line = f"[{ts}] !! JS ERROR: {message.get('description')}\n{message.get('stack','')}"
            print(line)
            with self.lock:
                self.log_fh.write(json.dumps({"ts": ts, "error": message}, ensure_ascii=False) + "\n")
                self.log_fh.flush()
            return
        if message["type"] != "send":
            return
        payload = message["payload"]
        # 元信息进 JSONL;字节附件单独落盘
        with self.lock:
            if data is not None and payload.get("t") in ("resp_body", "req_body"):
                h = payload["handle"]
                offset = self._body_offset[h]
                kind = payload["t"]  # resp_body / req_body
                fname = f"{h.replace('0x','')}.{kind}.{offset:08x}.bin"
                bpath = self.bodies_dir / fname
                bpath.write_bytes(data)
                self.body_files[h].append((kind, offset, bpath.name, len(data)))
                self._body_offset[h] = offset + len(data)
                record = {"ts": ts, **payload, "data_file": fname, "data_len": len(data)}
                record.pop("b64", None)
            else:
                record = {"ts": ts, **payload}
            self.log_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.log_fh.flush()
        self._route(payload, ts, data)

    def _route(self, p: dict, ts: str, data):
        t = p.get("t")
        if t == "note":
            print(f"[{ts}] hook: {p['msg']}")
        elif t == "ready":
            print(f"[{ts}] === HOOK READY ===")
        elif t == "connect":
            self.conn[p["handle"]] = {"server": p["server"], "port": p["port"]}
        elif t == "request":
            self._on_request(p, ts)
        elif t == "req_headers":
            self._on_headers(p, ts)
        elif t == "send":
            pass  # 标记请求已发送,信息有限
        elif t == "req_body":
            self._on_req_body(p, ts, data)
        elif t == "resp_body":
            self._on_resp_body(p, ts, data)
        elif t == "query_info":
            self._on_query_info(p, ts)

    def _on_request(self, p, ts):
        h = p["handle"]
        self.tx[h].update({
            "server": p.get("server"), "port": p.get("port"),
            "verb": p.get("verb"), "obj": p.get("obj"),
            "headers": [], "req_body_b64": [],
            "resp_body_b64": [], "query": [],
            "start_ts": ts,
        })
        srv = p.get("server") or "?"
        mark = ""
        if srv and any(th in srv for th in TARGET_HOSTS):
            mark = "  ★★★ TARGET"
        self.request_handles.append(h)
        print(f"[{ts}] REQ {h} {p.get('verb')} {srv}:{p.get('port')}{p.get('obj','')}{mark}")

    def _on_headers(self, p, ts):
        h = p["handle"]
        tx = self.tx[h]
        hdrs = p.get("headers") or ""
        tx["headers"].append(hdrs)
        # 只对目标主机详细打印
        if tx.get("server") and any(th in (tx["server"] or "") for th in TARGET_HOSTS):
            for line in hdrs.split("\r\n"):
                if line.strip():
                    print(f"[{ts}]   | {line}")

    def _on_req_body(self, p, ts, data):
        h = p["handle"]
        tx = self.tx[h]
        tx.setdefault("req_body_len", 0)
        tx["req_body_len"] += p.get("len", 0)
        raw = data or b""
        preview = _safe_preview(raw)
        if tx.get("server") and any(th in (tx["server"] or "") for th in TARGET_HOSTS):
            print(f"[{ts}]   >> body {p.get('len')}B {preview}")

    def _on_resp_body(self, p, ts, data):
        h = p["handle"]
        tx = self.tx[h]
        tx.setdefault("resp_body_len", 0)
        tx["resp_body_len"] += p.get("len", 0)
        raw = data or b""
        preview = _safe_preview(raw)
        if tx.get("server") and any(th in (tx["server"] or "") for th in TARGET_HOSTS):
            print(f"[{ts}]   << body {p.get('len')}B {preview}")

    def _assemble_body(self, h: str, kind: str) -> bytes:
        """按 offset 顺序拼某 handle 的 req_body/resp_body 字节。"""
        parts = []
        for k, off, fname, n in sorted(self.body_files.get(h, []), key=lambda x: x[1]):
            if k == kind:
                parts.append((off, self.bodies_dir / fname))
        if not parts:
            return b""
        parts.sort(key=lambda x: x[0])
        out = bytearray()
        cur = 0
        for off, fp in parts:
            if off > cur:
                out += b"\x00" * (off - cur)  # 理论上不应有 gap
            chunk = fp.read_bytes()
            out += chunk
            cur = off + len(chunk)
        return bytes(out)

    def _on_query_info(self, p, ts):
        h = p["handle"]
        tx = self.tx[h]
        tx["query"].append({"level": p.get("infoLevel"), "value": p.get("value")})
        # 只打印有意义的响应元
        lvl = p.get("infoLevel", "")
        interesting = ("STATUS_CODE", "STATUS_TEXT", "CONTENT_LENGTH", "ETAG",
                       "LAST_MODIFIED", "CONTENT_RANGE", "ACCEPT_RANGES", "LOCATION")
        if any(k in lvl for k in interesting):
            srv = tx.get("server") or ""
            if any(th in srv for th in TARGET_HOSTS) or "10jqka" in srv:
                print(f"[{ts}]   {lvl}: {p.get('value')}")

    def write_summary(self, path: pathlib.Path):
        lines = []
        lines.append(f"# frida hook summary ({now_str()})")
        lines.append(f"# target hosts: {TARGET_HOSTS}")
        lines.append(f"# total requests captured: {len(self.request_handles)}")
        lines.append("")
        for h in self.request_handles:
            tx = self.tx[h]
            srv = tx.get("server") or "?"
            is_target = any(th in srv for th in TARGET_HOSTS)
            lines.append("=" * 70)
            lines.append(f"[{tx.get('start_ts')}] handle={h} "
                        f"{'★TARGET ' if is_target else ''}{tx.get('verb')} "
                        f"{srv}:{tx.get('port')}{tx.get('obj','') or ''}")
            for hdrs in tx.get("headers", []):
                for line in hdrs.split("\r\n"):
                    if line.strip():
                        lines.append(f"  > {line}")
            rb = tx.get("req_body_len", 0)
            if rb:
                lines.append(f"  >> request body {rb}B")
                raw = self._assemble_body(h, "req_body")
                lines.append(_hex_dump(raw, max_bytes=512))
            q = tx.get("query", [])
            if q:
                lines.append("  response meta:")
                for item in q:
                    lines.append(f"    {item['level']}: {item['value']}")
            resp = tx.get("resp_body_len", 0)
            if resp:
                lines.append(f"  << response body {resp}B")
                raw = self._assemble_body(h, "resp_body")
                # 大响应单独落盘整块,摘要里只放 hex 头
                whole_path = self.bodies_dir / f"{h.replace('0x','')}.resp_body.whole.bin"
                whole_path.write_bytes(raw)
                lines.append(f"  (完整响应字节: {whole_path.name})")
                lines.append(_hex_dump(raw, max_bytes=2048))
            elif tx.get("query"):
                lines.append("  << (no body captured)")
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        print(f"\n摘要已写入 {path}")


def _safe_preview(raw: bytes, n=80) -> str:
    if not raw:
        return "<empty>"
    head = raw[:n]
    try:
        # 多数是文本
        return "text:" + head.decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
    except Exception:
        return "hex:" + head.hex()


def _hex_dump(raw: bytes, max_bytes=512) -> str:
    chunk = raw[:max_bytes]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"  {i:04x}  {hex_part:<48}  {ascii_part}")
    if len(raw) > max_bytes:
        lines.append(f"  ... ({len(raw)} bytes total, truncated)")
    return "\n".join(lines)


# ── _entries 文件监控 ──────────────────────────────────────────
class EntriesWatcher(threading.Thread):
    """每秒 snapshot 一次,检测到 version 变化就高亮 + 备份变化文件。"""

    def __init__(self, out_dir: pathlib.Path, collector: HookCollector):
        super().__init__(daemon=True)
        self.out_dir = out_dir
        self.collector = collector
        self.stop_flag = threading.Event()
        self.prev = bl.snapshot()
        self.changed_count = 0
        # 启动时把 baseline 落盘
        (out_dir / "entries_before.txt").write_text(_fmt_snapshot(self.prev), encoding="utf-8")

    def run(self):
        while not self.stop_flag.is_set():
            time.sleep(1.0)
            try:
                cur = bl.snapshot()
            except Exception as e:
                continue
            diff = bl.diff_snapshots(self.prev, cur)
            if diff:
                self.changed_count += 1
                ts = now_str()
                print(f"\n[{ts}] ★★★ _entries CHANGED ★★★")
                for line in diff:
                    print(f"  {line}")
                print()
                # 备份变化后的 _entries + 变化文件
                snap_dir = self.out_dir / f"entries_change_{now_ts()}"
                snap_dir.mkdir(exist_ok=True)
                try:
                    import shutil
                    shutil.copy2(bl.DEFAULT_ENTRIES, snap_dir / "_entries")
                    # 备份所有变化文件
                    cur_files = set(cur.get("files", {}).keys())
                    old_files = set(self.prev.get("files", {}).keys())
                    changed_names = {n for n in (cur_files | old_files)
                                   if cur.get("files", {}).get(n) != self.prev.get("files", {}).get(n)}
                    for name in changed_names:
                        src = bl.DEFAULT_BLOCK_DIR / name
                        if src.exists():
                            shutil.copy2(src, snap_dir / name)
                except Exception as e:
                    print(f"  备份变化文件失败: {e}")
                self.prev = cur
        # 结束时落盘最终快照
        (self.out_dir / "entries_after.txt").write_text(_fmt_snapshot(self.prev), encoding="utf-8")


def _fmt_snapshot(snap: dict) -> str:
    lines = [
        f"version = {snap.get('version')}",
        f"last_request_download = {snap.get('last_request_download')} -> {bl.fmt_ts(snap.get('last_request_download'))}",
        f"last_download = {snap.get('last_download')} -> {bl.fmt_ts(snap.get('last_download'))}",
        f"entries_sha256 = {snap.get('entries_sha')}",
        f"files = {len(snap.get('files', {}))}",
        "",
    ]
    for name in sorted(snap.get("files", {})):
        v = snap["files"][name]
        lines.append(f"  {name}: v={v.get('manifest_ver')} crc={v.get('manifest_crc')} "
                    f"size={v.get('size','-')} ok={v.get('crc_ok','-')}")
    return "\n".join(lines)


# ── main ───────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="抓板块云同步 HTTPS 明文")
    ap.add_argument("--duration", type=int, default=600, help="抓包时长秒(默认 600)")
    ap.add_argument("--spawn", action="store_true", default=True,
                    help="spawn 同花顺(默认开启,可用 --no-spawn 关闭)")
    ap.add_argument("--no-spawn", dest="spawn", action="store_false", help="不 spawn,改用 attach")
    ap.add_argument("--attach", default=None, help="attach 到指定进程名(默认 hexin.exe)")
    ap.add_argument("--exe", default=HEXIN_EXE, help=f"同花顺 exe 路径(默认 {HEXIN_EXE})")
    ap.add_argument("--no-dumpcap", action="store_true", help="不启动 dumpcap(默认启动)")
    ap.add_argument("--iface", default=None, help="dumpcap 网卡编号(不指定则交互选)")
    args = ap.parse_args()

    out_dir = CAPTURES_DIR / f"blockupdate_{now_ts()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"产物目录: {out_dir}")

    # 1. frida
    print("\n=== Frida hook ===")
    try:
        session, pid, dev = make_frida_session(args.spawn, args.attach, args.exe)
    except Exception as e:
        print(f"✗ frida 初始化失败: {e}")
        return
    collector = HookCollector(out_dir / "frida_log.jsonl", out_dir / "bodies")
    script = session.create_script(HOOK_JS.read_text(encoding="utf-8"))
    script.on("message", collector.on_message)
    script.load()
    if args.spawn:
        print(f"  resuming pid={pid} ...")
        dev.resume(pid)

    # 2. 文件监控
    print("\n=== _entries 监控 ===")
    watcher = EntriesWatcher(out_dir, collector)
    watcher.start()
    print(f"  baseline: version={watcher.prev['version']} files={len(watcher.prev['files'])}")

    # 3. dumpcap
    dumpcap_proc = None
    pcap_path = None
    if not args.no_dumpcap:
        print("\n=== dumpcap ===")
        iface = args.iface
        if iface is None:
            iface = pick_iface()
        pcap_path = out_dir / f"cloud_{now_ts()}.pcap"
        dumpcap_proc = start_dumpcap(pcap_path, iface, args.duration)
        if dumpcap_proc:
            print(f"  抓 {args.duration}s -> {pcap_path}")
        else:
            print("  dumpcap 未启动,继续只靠 frida + 文件监控")

    # 4. 等待
    print("\n" + "=" * 60)
    print(f"抓包中 {args.duration}s。现在请在同花顺里登录,触发板块云同步。")
    print("  看到 cloud.10jqka.com.cn 的请求会高亮 ★★★")
    print("  Ctrl+C 可提前结束")
    print("=" * 60 + "\n")
    try:
        for i in range(args.duration):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n用户中断")

    # 5. 收尾
    print("\n=== 收尾 ===")
    try:
        collector.write_summary(out_dir / "frida_summary.txt")
    except Exception as e:
        print(f"写摘要失败: {e}")
    watcher.stop_flag.set()
    watcher.join(timeout=3)
    collector.close()
    if dumpcap_proc:
        try:
            dumpcap_proc.terminate()
            dumpcap_proc.wait(timeout=5)
        except Exception:
            pass
    try:
        session.detach()
    except Exception:
        pass

    print(f"\n完成。产物在 {out_dir}/")
    print(f"  _entries 变化次数: {watcher.changed_count}")
    if watcher.changed_count:
        print(f"  ★ 抓到了增量!检查 entries_change_* 目录")


if __name__ == "__main__":
    main()
