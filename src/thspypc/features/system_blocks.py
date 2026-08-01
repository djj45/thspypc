"""同花顺 PC 系统板块本地缓存解析（block_hq 数据域，纯函数、无网络）。

数据来源（hexin 安装目录，2026-07-29 版实测）：

- ``<hexin>/industry.ini``
    同花顺行业板块：``[industry]`` 881xxx 板块指数代码 → 成分股代码；
    ``[name]`` 881xxx → 中文名；``[hash]`` md5 校验。
- ``<hexin>/BlockUpdate/block_<ID>.ini``
    板块树叶子文件（概念/地域/港股/基金/指标股等）。``[BLOCK_NAME_MAP_TABLE]``
    保存十六进制 block_id → 名称（首行是根节点自己，如 ``2B=概念``）；
    ``[BLOCK_STOCK_CONTEXT]`` 保存 block_id → 成分股，形如
    ``33:000938,17:600519,-105:920045``；基金类还有 ``1(36):184*``
    前缀通配写法。
- ``<hexin>/BlockUpdate/block_tree.ini``
    ``[BLOCK_TREE_ROOT]`` → ``[@10001]`` 列出全部根板块；``@节点`` 内
    key=block_id，value 为 ``@子节点`` 或数字叶子标记（实测 536871426 /
    536871427，均表示普通叶子，无业务分支）。

设计约定：

- 稳定 ID：行业板块用 ``881xxx``（十进制，与 q.10jqka.com.cn
  ``thshy/detail/code/881xxx/`` 一致）；概念/地域等用十六进制 block_id
  （如 ``C024``＝BC电池），大小写不敏感、统一大写。
- 本模块只做文本解析，不做 IO 错误兼容与缓存；上层
  :class:`thspypc.services.system_blocks.SystemBlocksService` 负责目录发现、
  按需加载与进程内缓存。
"""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass

# 板块树根节点（block_tree.ini 的 [BLOCK_TREE_ROOT] 指向的固定根）
_TREE_ROOT_NODE = "10001"

# 数字叶子标记的高位（其余位无业务含义；实测 0x20000002/0x20000003）
_LEAF_MARKER_BASE = 0x20000000


@dataclass(frozen=True)
class BlockStock:
    """板块成分股条目。

    Attributes:
        code: 6 位证券代码；``pattern=True`` 时为前缀（如 ``184``）。
        market: hexin 数字市场码字符串（``17`` 沪A/科创、``33`` 深A/创业、
            ``20``/``36`` 沪深基金、``-105`` 北交所等），行业板块由代码前缀推断。
        pattern: True 表示原文件是 ``N(market):prefix*`` 前缀通配写法，
            实际成分股需按该前缀展开（基金/指数类）。
    """

    code: str
    market: str
    pattern: bool = False

    def __post_init__(self) -> None:
        if self.pattern and self.code.endswith("*"):
            object.__setattr__(self, "code", self.code.rstrip("*"))


@dataclass(frozen=True)
class SystemBlock:
    """系统板块实体（只读）。

    Attributes:
        block_id: 稳定 ID。行业为 ``881xxx``；其余为十六进制 block_id（大写）。
        name: 板块中文名。
        category: 分类键（``industry``/``concept``/``region``/``hk``/
            ``fund``/...），也接受原始文件 ID（如 ``2B``）。
        category_name: 分类中文名（如 ``概念``）。
        source: 来源文件（``industry.ini`` 或 ``block_2B.ini``）。
        parent_id: 板块树中的父级 block_id（无则为 None）。
    """

    block_id: str
    name: str
    category: str
    category_name: str
    source: str
    parent_id: str | None = None


def normalize_block_id(block_id: str) -> str:
    """规范化板块 ID：行业 881xxx 原样；其余十六进制 ID 统一大写。"""
    block_id = block_id.strip()
    if block_id.isdigit():
        return block_id
    return block_id.upper()


def _split_ini_sections(text: str) -> list[tuple[str, list[str]]]:
    """按 ``[section]`` 头切分 INI 文本（保留行顺序，容忍空行）。"""
    sections: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            if current is not None:
                sections.append(current)
            current = (line[1:-1].strip(), [])
        elif current is not None and line and "=" in line:
            current[1].append(line)
    if current is not None:
        sections.append(current)
    return sections


def parse_block_ini(
    text: str,
) -> tuple[dict[str, str], dict[str, tuple[BlockStock, ...]]]:
    """解析 ``BlockUpdate/block_*.ini``，返回 (名称表, 成分股表)。

    Args:
        text: 文件全文（GBK 解码后传入）。

    Returns:
        (names, constituents)：names 为 block_id→中文名（含根节点自己）；
        constituents 为 block_id→成分股元组（无成分股的板块不出现在此表）。
    """
    names: dict[str, str] = {}
    constituents: dict[str, tuple[BlockStock, ...]] = {}
    for section, lines in _split_ini_sections(text):
        if section == "BLOCK_NAME_MAP_TABLE":
            for line in lines:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().rstrip(";").strip()
                if key:
                    names[normalize_block_id(key)] = value
        elif section == "BLOCK_STOCK_CONTEXT":
            for line in lines:
                key, _, value = line.partition("=")
                key = key.strip()
                if not key:
                    continue
                stocks = parse_block_context(value)
                if stocks:
                    constituents[normalize_block_id(key)] = stocks
    return names, constituents


_MARKET_PREFIX_RE = re.compile(r"^(-?\d+)\s*\(\s*(\d+)\s*\)\s*:\s*([^*]+)\*$")
_MARKET_CODE_RE = re.compile(r"^(-?\d+)\s*:\s*([^,]+)$")


def parse_block_context(raw: str) -> tuple[BlockStock, ...]:
    """解析 ``[BLOCK_STOCK_CONTEXT]`` 的一行成分股列表。

    支持两种写法：

    - 显式：``33:000938,17:600519,-105:920045``
    - 前缀通配：``1(36):184*``（基金类，N=数量未知，仅保留前缀+市场码）
    """
    result: list[BlockStock] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        m = _MARKET_PREFIX_RE.match(part)
        if m:
            result.append(
                BlockStock(
                    code=m.group(3).strip().upper(),
                    market=m.group(2).strip(),
                    pattern=True,
                )
            )
            continue
        m = _MARKET_CODE_RE.match(part)
        if m:
            result.append(
                BlockStock(
                    code=m.group(2).strip(),
                    market=m.group(1).strip(),
                )
            )
    return tuple(result)


def parse_industry_ini(
    text: str,
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    """解析 ``industry.ini``，返回 (名称表, 成分股表)。

    Args:
        text: 文件全文（GBK 解码后传入）。

    Returns:
        (names, constituents)：names 为 ``881xxx``→中文名；constituents 为
        ``881xxx``→成分股代码元组（原文件不带市场码）。
    """
    names: dict[str, str] = {}
    constituents: dict[str, tuple[str, ...]] = {}
    for section, lines in _split_ini_sections(text):
        if section == "name":
            for line in lines:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().rstrip(";").strip()
                if key:
                    names[key] = value
        elif section == "industry":
            for line in lines:
                key, _, value = line.partition("=")
                key = key.strip()
                if not key:
                    continue
                codes = tuple(
                    part.strip()
                    for part in value.split(",")
                    if part.strip()
                )
                if codes:
                    constituents[key] = codes
    return names, constituents


def parse_block_tree(text: str) -> dict[str, dict[str, str]]:
    """解析 ``block_tree.ini``，返回 节点ID → {子 block_id: 值}。

    值有两种：``@<节点ID>``（子树分组）或数字（叶子标记）。
    根节点键为 ``10001``（[BLOCK_TREE_ROOT] 的 ``1=@10001``）。
    """
    tree: dict[str, dict[str, str]] = {}
    for section, lines in _split_ini_sections(text):
        if not section.startswith("@"):
            continue
        node = section[1:].strip()
        children: dict[str, str] = {}
        for line in lines:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key:
                children[normalize_block_id(key)] = value
        tree[node] = children
    if _TREE_ROOT_NODE not in tree:
        # 兼容 [BLOCK_TREE_ROOT] 未归一化的情况：取第一个 @ 节点作为根。
        roots = [
            value[1:]
            for section, lines in _split_ini_sections(text)
            if section == "BLOCK_TREE_ROOT"
            for _key, value in (line.partition("=")[::2] for line in lines)
            if value.startswith("@")
        ]
        if roots and roots[0] in tree:
            return tree
    return tree


def tree_root_children(
    tree: dict[str, dict[str, str]],
) -> dict[str, str]:
    """返回板块树根节点的直接子级 {block_id: 值}。"""
    return dict(tree.get(_TREE_ROOT_NODE, {}))


def build_parent_map(
    tree: dict[str, dict[str, str]],
) -> dict[str, str]:
    """按板块树推导 block_id → 父级 block_id（子树节点 key 即父板块 ID）。"""
    parent: dict[str, str] = {}

    def walk(node: str, ancestor: str | None) -> None:
        for child_id, value in tree.get(node, {}).items():
            if value.startswith("@"):
                if ancestor is not None:
                    parent.setdefault(child_id, ancestor)
                walk(value[1:], child_id)
            else:
                if ancestor is not None:
                    parent.setdefault(child_id, ancestor)

    roots = tree_root_children(tree)
    for root_id, value in roots.items():
        parent.setdefault(root_id, root_id)
        if value.startswith("@"):
            walk(value[1:], root_id)
    return parent


def infer_market_from_code(code: str) -> str | None:
    """按 A 股代码前缀推断 hexin 数字市场码（行业板块成分股无市场码时用）。"""
    if len(code) < 3:
        return None
    p = code[:3]
    if p in ("600", "601", "603", "605", "688", "689"):
        return "17"
    if p in ("000", "001", "002", "003", "300", "301", "302"):
        return "33"
    if p in ("430", "830", "831", "832", "833", "834", "835", "836", "837", "838", "839", "870", "871", "872", "873", "920"):
        return "-105"
    return None
