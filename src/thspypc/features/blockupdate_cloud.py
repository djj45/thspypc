"""系统板块云同步协议（通道 C：cloud.10jqka.com.cn 匿名 ZIP）。

逆向来源：2026-08-11 Frida hook WinINet + curl 重放，详见
``docs/handoffs/HANDOFF_BLOCKUPDATE_CLOUD_SYNC_20260810.md`` 的「2026-08-11 二次突破」节。

协议要点
--------
- **匿名 GET**，无 header / cookie / 鉴权，跨平台只需 ``urllib + zipfile``。
- URL::

      https://cloud.10jqka.com.cn/storage/stockblock_ths/v2_hqtyb_client/
          &storetype~0&version~N&reqtype~download

  注意参数用 ``~`` 分隔（客户端把整段 URL-encode 成
  ``%26storetype%7E0%26version%7EN%26reqtype%7Edownload``）。
- 响应二态：
    * ``N < 当前版本`` → ``application/zip``，含 58 个 ``block_*.ini`` 全量包
    * ``N >= 当前版本`` → ``text/xml;charset=GBK``，
      ``<storage_download><ret code="0" msg="当前已是最新的版本"/></storage_download>``
- 只支持「全量或无更新」，没有细粒度增量；ZIP 压缩比 ~4:1，全量兜底可接受。

ZIP 元信息（用于重建 ``_entries``）
-----------------------------------
- 归档注释（``ZipFile.comment``）：``#@language=zh_CN.GBK\\r\\nmax_version=205176``
  → ``max_version`` 就是 ``_entries`` 的 ``system.version``。
- 每个 ``ZipInfo.comment``：``version=205081;crc=;diff=0;``
  → 每个文件各自的版本号（``system.version`` = 所有文件里的最大值）。
- ``crc=`` 恒为空，客户端自己用 ``zlib.crc32`` 算内容 CRC 填进 ``_entries``。

本模块是纯协议层：``fetch_block_zip`` 取字节、``parse_block_zip`` 拆出文件清单和元信息、
``build_entries_text`` 重建 ``_entries`` 文本。落盘编排由调用方（service 层）做。
"""
from __future__ import annotations

import io
import logging
import re
import urllib.request
import zipfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# cloud.10jqka.com.cn 系统板块同步入口（交接文档第 27 行 BlockUpdateURL 的实际下载路径）。
CLOUD_HOST = "cloud.10jqka.com.cn"
CLOUD_PATH_BASE = "/storage/stockblock_ths/v2_hqtyb_client/"
# storetype 实测 0~7 返回完全相同的 ZIP，用 0。
STORETYPE = "0"

# 「当前已是最新的版本」响应里的固定字样（GBK）。
_UPTODATE_MSG = "当前已是最新的版本"
_UPTODATE_MARKER = b"<storage_download>"


@dataclass(frozen=True)
class BlockFileEntry:
    """ZIP 内单个 block_*.ini 的元信息。"""

    name: str
    version: int
    crc32: int  # 由内容计算的无符号 CRC32，与 _entries 记录一致


@dataclass(frozen=True)
class BlockZipManifest:
    """parse_block_zip 的结果。"""

    max_version: int  # system.version
    language: str  # 归档注释里的 language 字段（通常 zh_CN.GBK）
    files: list[BlockFileEntry]
    raw: bytes  # 原始 ZIP 字节，供调用方落盘或校验


class BlockCloudError(Exception):
    """系统板块云同步错误。"""


class BlockCloudUpToDate(BlockCloudError):
    """服务端返回「当前已是最新的版本」，无需下载。"""


def build_download_url(version: int) -> str:
    """构造下载 URL。

    参数用 ``~`` 分隔（与同花顺客户端抓包一致），整段放在 path 后面。
    """
    return (
        f"https://{CLOUD_HOST}{CLOUD_PATH_BASE}"
        f"&storetype~{STORETYPE}&version~{version}&reqtype~download"
    )


def fetch_block_zip(version: int, *, timeout: float = 60) -> bytes:
    """GET 系统板块同步包。

    返回 ZIP 原始字节。若服务端返回「无更新」XML，抛 :class:`BlockCloudUpToDate`。
    其它失败抛 :class:`BlockCloudError`。
    """
    url = build_download_url(version)
    req = urllib.request.Request(url, method="GET")
    # 不带任何 header：抓包确认同花顺请求里只有 Connection: close，且服务端不校验 UA。
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except Exception as exc:  # urllib 抛 URLError/HTTPError 等
        raise BlockCloudError(f"GET {url} 失败: {exc}") from exc

    if data[:2] == b"PK":
        return data
    if _UPTODATE_MARKER in data:
        raise BlockCloudUpToDate(_uptodate_msg(data))
    raise BlockCloudError(
        f"未知响应 (前 80 字节): {data[:80]!r}"
    )


def _uptodate_msg(data: bytes) -> str:
    try:
        text = data.decode("gbk", errors="replace")
        m = re.search(r'msg="([^"]+)"', text)
        return m.group(1) if m else _UPTODATE_MSG
    except Exception:
        return _UPTODATE_MSG


def _parse_archive_comment(comment: bytes) -> tuple[int, str]:
    """解析归档注释 ``#@language=zh_CN.GBK\\r\\nmax_version=205176``。"""
    text = comment.decode("gbk", errors="replace")
    language = ""
    max_version = 0
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#@language="):
            language = line.split("=", 1)[1]
        elif line.startswith("max_version="):
            try:
                max_version = int(line.split("=", 1)[1])
            except ValueError:
                pass
    return max_version, language


_FILE_COMMENT_RE = re.compile(r"version=(\d+)")


def _parse_file_comment(comment: bytes) -> int:
    """解析单个文件注释 ``version=205081;crc=;diff=0;``，取 version。"""
    if not comment:
        return 0
    text = comment.decode("gbk", errors="replace")
    m = _FILE_COMMENT_RE.search(text)
    return int(m.group(1)) if m else 0


def parse_block_zip(zip_bytes: bytes) -> BlockZipManifest:
    """解析 ZIP 字节，返回清单（含每个文件的 CRC32）。

    CRC32 用 :func:`zlib.crc32` 算文件**解压后内容**，与 ``_entries`` 记录对齐。
    """
    import zlib

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise BlockCloudError(f"非合法 ZIP: {exc}") from exc

    max_version, language = _parse_archive_comment(zf.comment)

    files: list[BlockFileEntry] = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        content = zf.read(info.filename)
        crc = zlib.crc32(content) & 0xFFFFFFFF
        ver = _parse_file_comment(info.comment)
        # 文件 comment 没有 version 时，退回到 max_version（实测不会发生）。
        if ver == 0:
            ver = max_version
        files.append(BlockFileEntry(name=info.filename, version=ver, crc32=crc))

    if max_version == 0 and files:
        # 归档注释解析失败时，用文件 version 最大值兜底。
        max_version = max(f.version for f in files)

    return BlockZipManifest(
        max_version=max_version, language=language, files=files, raw=zip_bytes
    )


def build_entries_text(manifest: BlockZipManifest, *, now_ts: int | None = None) -> str:
    """重建 ``_entries`` 文本，格式与同花顺客户端落盘一致。

    ``now_ts`` 缺省取当前时间戳，写入 ``last_request_download`` / ``last_download``。
    """
    import time

    ts = int(now_ts) if now_ts is not None else int(time.time())
    lines = [
        "[system]",
        f"last_request_download={ts}",
        f"last_download={ts}",
        f"version={manifest.max_version}",
        "[download_file_list]",
    ]
    for f in sorted(manifest.files, key=lambda x: x.name):
        lines.append(f"{f.name}={f.crc32},{f.version}")
    return "\n".join(lines) + "\n"
