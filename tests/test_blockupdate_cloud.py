"""``thspypc.features.blockupdate_cloud`` 的离线契约测试。

fixture ``tests/fixtures/blockupdate/cloud_zip_v205176.zip`` 是 2026-08-11 从
``cloud.10jqka.com.cn`` 实抓的全量 ZIP（version~0），解压后 58 个 ``block_*.ini``
与本机 ``C:\\同花顺软件\\同花顺\\BlockUpdate`` 字节一致。期望值取自同花顺客户端
本地生成的 ``_entries``（权威真值）。

详见 ``docs/handoffs/HANDOFF_BLOCKUPDATE_CLOUD_SYNC_20260810.md``。
"""
from __future__ import annotations

import json
import pathlib

import pytest

from thspypc.features import blockupdate_cloud as bc

FIX_DIR = pathlib.Path(__file__).parent / "fixtures" / "blockupdate"
ZIP_PATH = FIX_DIR / "cloud_zip_v205176.zip"
EXPECTED_PATH = FIX_DIR / "cloud_zip_expected.json"


@pytest.fixture(scope="module")
def zip_bytes() -> bytes:
    return ZIP_PATH.read_bytes()


@pytest.fixture(scope="module")
def expected() -> dict:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


# ── URL 构造 ────────────────────────────────────────────────────


def test_build_download_url_contains_required_params():
    url = bc.build_download_url(205176)
    # 关键参数必须齐全
    assert "cloud.10jqka.com.cn/storage/stockblock_ths/v2_hqtyb_client/" in url
    assert "storetype~0" in url
    assert "version~205176" in url
    assert "reqtype~download" in url


def test_build_download_url_version_inlined():
    assert "version~0" in bc.build_download_url(0)
    assert "version~99999" in bc.build_download_url(99999)


# ── parse_block_zip ────────────────────────────────────────────


def test_parse_zip_returns_manifest(zip_bytes, expected):
    manifest = bc.parse_block_zip(zip_bytes)
    assert isinstance(manifest, bc.BlockZipManifest)
    assert manifest.max_version == expected["system_version"]
    assert len(manifest.files) == expected["file_count"]


def test_parse_zip_max_version_from_archive_comment(zip_bytes, expected):
    """system.version 来自 ZIP 归档注释里的 max_version=。"""
    manifest = bc.parse_block_zip(zip_bytes)
    assert manifest.max_version == 205176


def test_parse_zip_language(zip_bytes):
    manifest = bc.parse_block_zip(zip_bytes)
    assert manifest.language == "zh_CN.GBK"


def test_parse_zip_file_crc_matches_entries(zip_bytes, expected):
    """每个文件的 CRC32 必须与 _entries 记录一致（字节级真值校验）。"""
    manifest = bc.parse_block_zip(zip_bytes)
    by_name = {f.name: f for f in manifest.files}
    for name, want in expected["sample_files"].items():
        assert name in by_name, f"缺 {name}"
        assert by_name[name].crc32 == want["crc32"], f"{name} crc 不匹配"
        assert by_name[name].version == want["version"], f"{name} version 不匹配"


def test_parse_zip_block_C0C5_is_max_version(zip_bytes):
    """版本最高的文件 block_C0C5.ini 的 version 应等于 max_version。"""
    manifest = bc.parse_block_zip(zip_bytes)
    c0c5 = next(f for f in manifest.files if f.name == "block_C0C5.ini")
    assert c0c5.version == manifest.max_version


def test_parse_zip_raw_preserved(zip_bytes):
    """manifest.raw 保留原始 ZIP 字节，供调用方落盘。"""
    manifest = bc.parse_block_zip(zip_bytes)
    assert manifest.raw == zip_bytes


# ── build_entries_text ─────────────────────────────────────────


def test_build_entries_has_system_and_file_list(zip_bytes, expected):
    manifest = bc.parse_block_zip(zip_bytes)
    text = bc.build_entries_text(manifest, now_ts=1786450828)
    assert "[system]" in text
    assert "[download_file_list]" in text
    assert f"version={expected['system_version']}" in text
    assert "last_request_download=1786450828" in text
    assert "last_download=1786450828" in text


def test_build_entries_file_lines_format(zip_bytes, expected):
    """每行格式 name=crc32,version，与 _entries 一致。"""
    manifest = bc.parse_block_zip(zip_bytes)
    text = bc.build_entries_text(manifest, now_ts=1786450828)
    for name, want in expected["sample_files"].items():
        line = f"{name}={want['crc32']},{want['version']}"
        assert line in text, f"缺 {line}"


def test_build_entries_block_C0C5_line_matches_local(zip_bytes):
    """与本地 _entries 的 block_C0C5.ini 行逐字一致（端到端真值）。"""
    manifest = bc.parse_block_zip(zip_bytes)
    text = bc.build_entries_text(manifest, now_ts=1786450828)
    assert "block_C0C5.ini=1704934322,205176" in text


# ── 错误路径 ────────────────────────────────────────────────────


def test_parse_bad_zip_raises():
    with pytest.raises(bc.BlockCloudError):
        bc.parse_block_zip(b"not a zip at all")


def test_fetch_up_to_date_detection(monkeypatch):
    """模拟服务端返回「当前已是最新的版本」XML，应抛 BlockCloudUpToDate。"""
    xml = (
        '<?xml version="1.0" encoding="gbk"?>\n'
        '<storage_download>\n'
        '<ret code="0" msg="当前已是最新的版本" systime="2026-08-11 20:36:03"/>\n'
        '</storage_download>\n'
    ).encode("gbk")

    class _FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return xml

    def fake_urlopen(req, timeout=None):
        return _FakeResp()

    monkeypatch.setattr(bc.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(bc.BlockCloudUpToDate):
        bc.fetch_block_zip(205176)


def test_fetch_unknown_response_raises(monkeypatch):
    class _FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return b"something weird"

    monkeypatch.setattr(bc.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp())
    with pytest.raises(bc.BlockCloudError):
        bc.fetch_block_zip(0)
