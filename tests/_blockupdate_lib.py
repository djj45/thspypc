# -*- coding: utf-8 -*-
"""板块云同步 (BlockUpdate / cloud.10jqka.com.cn) 抓包辅助库。

提供 _entries 解析、版本/CRC32 模型、文件快照与 diff,被以下脚本复用:

    tests/capture_blockupdate_cloud.py   # dumpcap + frida + 文件监控三合一
    tests/watch_blockupdate_entries.py   # 只监控 _entries 变化

详见 docs/handoffs/HANDOFF_BLOCKUPDATE_CLOUD_SYNC_20260810.md。
"""
from __future__ import annotations

import configparser
import datetime
import hashlib
import io
import pathlib
import zlib

CST = datetime.timezone(datetime.timedelta(hours=8))

# C:\\同花顺软件\\同花顺\\BlockUpdate (交接文档确认的安装路径)
DEFAULT_BLOCK_DIR = pathlib.Path(r"C:\同花顺软件\同花顺\BlockUpdate")
DEFAULT_ENTRIES = DEFAULT_BLOCK_DIR / "__base_" / "_entries"


def parse_entries(path: pathlib.Path) -> configparser.ConfigParser:
    """读 _entries。该文件是带 BOM 的 GBK 文本,容错处理。"""
    cp = configparser.ConfigParser()
    cp.optionxform = str  # 保留 key 原样大小写
    raw = pathlib.Path(path).read_bytes()
    # 去 UTF-8/UTF-16 BOM,尝试多种编码
    for enc in ("utf-8-sig", "utf-8", "gbk", "utf-16"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("latin-1")
    cp.read_file(io.StringIO(text))
    return cp


def system_version(cp: configparser.ConfigParser) -> int:
    return int(cp["system"].get("version", "0"))


def fmt_ts(ts) -> str:
    if not ts:
        return "-"
    try:
        return datetime.datetime.fromtimestamp(int(ts), CST).strftime("%Y-%m-%d %H:%M:%S CST")
    except (ValueError, OSError):
        return str(ts)


def file_list(cp: configparser.ConfigParser) -> dict[str, tuple[int, int]]:
    """filename -> (crc32, version)。CRC32 是无符号形式。"""
    out: dict[str, tuple[int, int]] = {}
    section = cp["download_file_list"]
    for name, val in dict(section).items():
        # 格式: crc32,version
        parts = val.split(",")
        if len(parts) != 2:
            continue
        try:
            crc = int(parts[0])
            ver = int(parts[1])
        except ValueError:
            continue
        out[name] = (crc, ver)
    return out


def crc32_unsigned(data: bytes) -> int:
    """与 _entries 里记录的 crc32 对齐(无符号)。"""
    return zlib.crc32(data) & 0xFFFFFFFF


def snapshot(block_dir: pathlib.Path = DEFAULT_BLOCK_DIR) -> dict:
    """返回 {version, last_*, files:{name:(crc,ver,size,mtime,sha8)}, entries_sha}。"""
    entries_path = block_dir / "__base_" / "_entries"
    if not entries_path.exists():
        return {"version": None, "files": {}, "missing": True}
    cp = parse_entries(entries_path)
    st = cp["system"]
    snap = {
        "version": int(st.get("version", "0")),
        "last_request_download": st.get("last_request_download"),
        "last_download": st.get("last_download"),
        "entries_path": str(entries_path),
        "entries_sha": hashlib.sha256(entries_path.read_bytes()).hexdigest(),
        "files": {},
    }
    manifest = file_list(cp)
    for name, (crc, ver) in manifest.items():
        fp = block_dir / name
        if fp.exists():
            data = fp.read_bytes()
            snap["files"][name] = {
                "manifest_crc": crc,
                "manifest_ver": ver,
                "actual_crc": crc32_unsigned(data),
                "size": len(data),
                "crc_ok": crc32_unsigned(data) == crc,
                "mtime": fp.stat().st_mtime,
            }
        else:
            snap["files"][name] = {
                "manifest_crc": crc,
                "manifest_ver": ver,
                "missing": True,
            }
    return snap


def diff_snapshots(old: dict, new: dict) -> list[str]:
    """对比两次 snapshot,返回人类可读变更行列表。"""
    lines: list[str] = []
    if old.get("version") != new.get("version"):
        lines.append(
            f"[version] {old.get('version')} -> {new.get('version')}"
        )
    for key in ("last_request_download", "last_download"):
        if old.get(key) != new.get(key):
            lines.append(
                f"[{key}] {old.get(key)} ({fmt_ts(old.get(key))}) -> "
                f"{new.get(key)} ({fmt_ts(new.get(key))})"
            )
    if old.get("entries_sha") != new.get("entries_sha"):
        lines.append(
            f"[_entries sha256] {old.get('entries_sha','?')[:12]} -> "
            f"{new.get('entries_sha','?')[:12]}"
        )
    of = old.get("files", {})
    nf = new.get("files", {})
    changed = []
    for name in sorted(set(of) | set(nf)):
        a, b = of.get(name), nf.get(name)
        if a == b:
            continue
        if a is None:
            changed.append(f"  + {name}: 新文件 v{b.get('manifest_ver')} crc={b.get('manifest_crc')}")
        elif b is None:
            changed.append(f"  - {name}: 删除")
        else:
            av, bv = a.get("manifest_ver"), b.get("manifest_ver")
            ac, bc = a.get("manifest_crc"), b.get("manifest_crc")
            if av != bv or ac != bc:
                changed.append(
                    f"  ~ {name}: v{av}->v{bv} crc={ac}->{bc} "
                    f"(size {a.get('size','?')}->{b.get('size','?')})"
                )
            elif a.get("size") != b.get("size") or a.get("actual_crc") != b.get("actual_crc"):
                changed.append(
                    f"  ~ {name}: 清单不变但内容变 (size {a.get('size')}->{b.get('size')})"
                )
    if changed:
        lines.append("[changed files]")
        lines.extend(changed)
    return lines
