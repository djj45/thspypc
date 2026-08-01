"""系统板块只读 MVP 的离线单测 + 真实 hexin 安装冒烟测试。

解析层（features/system_blocks.py）用内嵌最小样本做纯函数测试；
服务层（services/system_blocks.py）用 tmp_path 构造目录结构；
真实安装测试在找到 hexin 时运行，未找到则 skip（验收口径：
“本地缓存 → 稳定 ID → 成分股”与 PC 客户端同源）。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.features.system_blocks import (
    BlockStock,
    SystemBlock,
    build_parent_map,
    infer_market_from_code,
    normalize_block_id,
    parse_block_context,
    parse_block_ini,
    parse_block_tree,
    parse_industry_ini,
    tree_root_children,
)
from thspypc.services.system_blocks import (
    SystemBlocksError,
    SystemBlocksService,
)


CONCEPT_SAMPLE = """\
[ConfigInfo]
ConfigName=stockblock_同花顺方案
ConfigVer=20260729.175500|20260729
[BLOCK_NAME_MAP_TABLE]
2B=概念
DBD0=地域类
C024=BC电池
C022=光刻机
[BLOCK_STOCK_CONTEXT]
C024=17:688981,17:603986,33:300750,33:002129,-105:920045
C022=17:688012,33:300236,
"""

TREE_SAMPLE = """\
[ConfigInfo]
ConfigName=stockblock_同花顺方案
[BLOCK_TREE_ROOT]
1=@10001
[@10001]
2B=@10043
47=@10071
[@10043]
DBD0=@66272
[@66272]
C024=536871427
C022=536871427
[@10071]
48=536871427
49=536871427
"""

INDUSTRY_SAMPLE = """\
[industry]
881101=603336,000998,920045
881121=688981,688825,002049,001309
[name]
881101=种植业与林业;
881121=半导体;
[hash]
md5=abc
"""

REGION_SAMPLE = """\
[ConfigInfo]
ConfigName=stockblock_同花顺方案
[BLOCK_NAME_MAP_TABLE]
47=地域
48=安徽
49=北京
[BLOCK_STOCK_CONTEXT]
48=33:000596,33:000630
49=17:600008,33:000402
"""


# ── 解析层：block_*.ini ──


def test_parse_block_ini_names_and_constituents():
    names, constituents = parse_block_ini(CONCEPT_SAMPLE)

    assert names["2B"] == "概念"
    assert names["C024"] == "BC电池"
    assert names["C022"] == "光刻机"
    assert constituents["C024"] == (
        BlockStock("688981", "17"),
        BlockStock("603986", "17"),
        BlockStock("300750", "33"),
        BlockStock("002129", "33"),
        BlockStock("920045", "-105"),
    )
    assert constituents["C022"] == (
        BlockStock("688012", "17"),
        BlockStock("300236", "33"),
    )


def test_parse_block_context_supports_prefix_wildcards():
    stocks = parse_block_context("1(36):184*,33:000938,2(20):513*")

    assert stocks == (
        BlockStock("184", "36", pattern=True),
        BlockStock("000938", "33"),
        BlockStock("513", "20", pattern=True),
    )


def test_normalize_block_id():
    assert normalize_block_id("c024") == "C024"
    assert normalize_block_id("881121") == "881121"
    assert normalize_block_id(" 2b ") == "2B"


# ── 解析层：industry.ini ──


def test_parse_industry_ini():
    names, constituents = parse_industry_ini(INDUSTRY_SAMPLE)

    assert names["881101"] == "种植业与林业"
    assert names["881121"] == "半导体"
    assert constituents["881121"] == ("688981", "688825", "002049", "001309")
    assert constituents["881101"] == ("603336", "000998", "920045")


def test_infer_market_from_code():
    assert infer_market_from_code("600519") == "17"
    assert infer_market_from_code("688981") == "17"
    assert infer_market_from_code("000938") == "33"
    assert infer_market_from_code("300750") == "33"
    assert infer_market_from_code("920045") == "-105"
    assert infer_market_from_code("123456") is None


# ── 解析层：block_tree.ini ──


def test_parse_block_tree_and_parent_map():
    tree = parse_block_tree(TREE_SAMPLE)
    roots = tree_root_children(tree)

    assert set(roots) == {"2B", "47"}
    assert roots["2B"] == "@10043"
    parents = build_parent_map(tree)

    assert parents["2B"] == "2B"
    assert parents["DBD0"] == "2B"
    assert parents["C024"] == "DBD0"
    assert parents["C022"] == "DBD0"
    assert parents["48"] == "47"


# ── 服务层：tmp 目录 ──


def _write_service_fixture(root: Path) -> SystemBlocksService:
    block_dir = root / "BlockUpdate"
    block_dir.mkdir(parents=True)
    (block_dir / "block_2B.ini").write_text(CONCEPT_SAMPLE, encoding="gbk")
    (block_dir / "block_47.ini").write_text(REGION_SAMPLE, encoding="gbk")
    (block_dir / "block_tree.ini").write_text(TREE_SAMPLE, encoding="gbk")
    (root / "industry.ini").write_text(INDUSTRY_SAMPLE, encoding="gbk")
    return SystemBlocksService(hexin_dir=str(root))


def test_service_categories_and_boards(tmp_path):
    service = _write_service_fixture(tmp_path)

    cats = service.categories()
    ids = {c["id"] for c in cats}
    assert "industry" in ids
    assert "concept" in ids
    assert "region" in ids

    industry = service.boards("industry")
    assert len(industry) == 2
    assert industry[1].block_id == "881121"
    assert industry[1].name == "半导体"
    assert industry[1].category == "industry"

    concept = service.boards("concept")
    assert {b.block_id for b in concept} == {"C024", "C022"}
    assert concept[0].parent_id == "DBD0"
    assert concept[0].category_name == "概念"

    # 文件 ID 与中文名都可以选分类
    assert {b.block_id for b in service.boards("2B")} == {"C024", "C022"}
    assert {b.block_id for b in service.boards("概念")} == {"C024", "C022"}


def test_service_constituents_and_lookup(tmp_path):
    service = _write_service_fixture(tmp_path)

    semis = service.constituents("881121")
    assert semis == [
        BlockStock("688981", "17"),
        BlockStock("688825", "17"),
        BlockStock("002049", "33"),
        BlockStock("001309", "33"),
    ]

    battery = service.constituents("c024")  # 大小写不敏感
    assert battery[0] == BlockStock("688981", "17")
    assert battery[-1] == BlockStock("920045", "-105")

    board = service.board("C024")
    assert isinstance(board, SystemBlock)
    assert board.name == "BC电池"
    assert service.board("999999") is None

    with pytest.raises(SystemBlocksError):
        service.constituents("999999")


def test_service_missing_install_raises():
    with pytest.raises(SystemBlocksError):
        SystemBlocksService(block_update_dir=r"C:\__no_such_ths_dir__")


# ── 真实 hexin 安装冒烟（本机验收口径，缺装则跳过）──


def _real_hexin_dir() -> str | None:
    for candidate in (
        os.environ.get("THS_HEXIN_DIR"),
        r"D:\同花顺软件\同花顺",
        r"C:\new_hxzq_hd",
    ):
        if candidate and Path(candidate, "BlockUpdate").is_dir():
            return candidate
    return None


@pytest.mark.skipif(_real_hexin_dir() is None, reason="本机未安装 hexin")
def test_real_install_smoke():
    service = SystemBlocksService(hexin_dir=_real_hexin_dir())

    cats = {c["id"]: c for c in service.categories()}
    assert cats["industry"]["board_count"] >= 80
    assert cats["concept"]["board_count"] >= 300

    semis = service.constituents("881121")
    assert len(semis) >= 50
    assert any(s.code == "688981" for s in semis)

    battery = service.constituents("C024")
    assert len(battery) >= 20

    all_boards = service.boards()
    ids = {b.block_id for b in all_boards}
    assert "881121" in ids
    assert "C024" in ids

    # 反向查询：中芯国际应属于半导体行业
    boards = service.stock_boards("688981")
    assert any(b.block_id == "881121" for b in boards)
