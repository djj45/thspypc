"""系统板块只读服务（行业/概念/地域/港股…）。

数据源为 hexin PC 安装目录下的 ``BlockUpdate/block_*.ini`` 与
``industry.ini``（本地 block_hq 缓存域），**不依赖登录、不走 8901**。

定位与约束（对齐 FEATURE_GAP_ROADMAP P0）：

- 只读 MVP：板块发现 → 稳定 ID → 成分股；不捆绑行情/排名/资金流。
- 目录发现：``$THS_HEXIN_DIR`` → 常见安装路径；也允许用
  ``THS_BLOCKUPDATE_DIR`` 直接指定 BlockUpdate 目录。
- 稳定 ID：行业板块 ``881xxx``（与 q.10jqka.com.cn
  ``thshy/detail/code/881xxx/`` 一致）；概念/地域等为十六进制 block_id
  （如 ``C024``=BC电池），统一大写。
- 分类键：``industry``/``concept``/``region``/``hk``/``fund`` 等语义别名，
  也可直接用原始文件 ID（``2B``/``47``/``7``/``2``…）。
"""
from __future__ import annotations

import logging
import os
import socket
from collections.abc import Callable
from pathlib import Path

from ..features.system_blocks import (
    BlockStock,
    SystemBlock,
    build_parent_map,
    infer_market_from_code,
    normalize_block_id,
    parse_block_ini,
    parse_block_tree,
    parse_industry_ini,
    tree_root_children,
)
from ..features.system_blocks_protocol import (
    PAGEID_BOARD_HISTORY,
    PAGEID_BOARD_HISTORY_L2,
    PAGEID_BOARD_LIST,
    PAGEID_BOARD_LIST_L2,
    PAGEID_BOARD_TL,
    PAGEID_BOARD_TL_L2,
    build_board_auction_query,
    build_board_constituents_query,
    build_board_list_query,
    build_board_timeline_query,
    parse_board_auction_response,
    parse_board_constituents_response,
    parse_board_quote_response,
    parse_board_timeline_response,
)
from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import ProtocolError
from ..models import AccountKind, Capability

logger = logging.getLogger(__name__)


class SystemBlocksError(Exception):
    """系统板块读取/解析错误。"""


FrameReader = Callable[[SocketLike], bytes]
Clock = Callable[[], float]


# 语义别名 → BlockUpdate 文件 ID（大小写不敏感）
CATEGORY_ALIASES: dict[str, str] = {
    "concept": "2B",
    "region": "47",
    "hk": "7",
    "fund": "2",
    "sw_industry": "DFF8",
    "nq_industry": "DACC",
    "index_stocks": "C6",
    "special_index": "C0C5",
    "nq": "D8CF",
    "us_etf": "D2DB",
}
_FILE_TO_ALIAS = {file_id: alias for alias, file_id in CATEGORY_ALIASES.items()}

_DEFAULT_HEXIN_DIRS = (
    r"D:\同花顺软件\同花顺",
    r"C:\new_hxzq_hd",
    r"C:\hexin",
    r"C:\同花顺软件\同花顺",
    r"D:\同花顺\同花顺",
)


def default_hexin_dir() -> str | None:
    """按 env/常见路径探测 hexin 安装目录。"""
    env_dir = os.environ.get("THS_HEXIN_DIR")
    if env_dir:
        return env_dir
    for candidate in _DEFAULT_HEXIN_DIRS:
        if Path(candidate).is_dir():
            return candidate
    return None


class SystemBlocksService:
    """系统板块只读服务，进程内按需加载并缓存解析结果。"""

    def __init__(
        self,
        hexin_dir: str | None = None,
        *,
        block_update_dir: str | None = None,
    ) -> None:
        if block_update_dir is None:
            hexin_dir = hexin_dir or default_hexin_dir()
            if hexin_dir is None:
                raise SystemBlocksError(
                    "未找到 hexin 安装目录：设置 THS_HEXIN_DIR 或传 hexin_dir"
                )
            block_update_dir = os.path.join(hexin_dir, "BlockUpdate")
        self._hexin_dir = hexin_dir
        self._block_update_dir = block_update_dir
        self._industry: tuple[dict[str, str], dict[str, tuple[str, ...]]] | None = None
        self._tree: dict[str, dict[str, str]] | None = None
        self._parents: dict[str, str] | None = None
        self._files: dict[str, tuple[dict[str, str], dict[str, tuple[BlockStock, ...]]]] = {}
        self._categories: list[dict] | None = None
        if not Path(block_update_dir).is_dir():
            raise SystemBlocksError(f"BlockUpdate 目录不存在: {block_update_dir}")

    @property
    def hexin_dir(self) -> str | None:
        return self._hexin_dir

    @property
    def block_update_dir(self) -> str:
        return self._block_update_dir

    # ── 内部加载 ──

    def _load_industry(self) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
        if self._industry is None:
            path = os.path.join(os.path.dirname(self._block_update_dir), "industry.ini")
            if not os.path.exists(path):
                path = os.path.join(self._block_update_dir, "..", "industry.ini")
            if not os.path.exists(path):
                raise SystemBlocksError(f"industry.ini 不存在: {path}")
            try:
                text = Path(path).read_text(encoding="gbk", errors="replace")
            except OSError as exc:
                raise SystemBlocksError(f"读取 industry.ini 失败: {exc}") from exc
            self._industry = parse_industry_ini(text)
            logger.info("系统板块：industry.ini 已加载（%d 个行业）",
                        len(self._industry[1]))
        return self._industry

    def _load_tree(self) -> dict[str, dict[str, str]]:
        if self._tree is None:
            path = os.path.join(self._block_update_dir, "block_tree.ini")
            try:
                text = Path(path).read_text(encoding="gbk", errors="replace")
            except OSError as exc:
                raise SystemBlocksError(f"读取 block_tree.ini 失败: {exc}") from exc
            self._tree = parse_block_tree(text)
            self._parents = build_parent_map(self._tree)
        return self._tree

    def _parent_map(self) -> dict[str, str]:
        self._load_tree()
        assert self._parents is not None
        return self._parents

    def _load_block_file(
        self, file_id: str
    ) -> tuple[dict[str, str], dict[str, tuple[BlockStock, ...]]]:
        file_id = file_id.upper()
        cached = self._files.get(file_id)
        if cached is not None:
            return cached
        path = os.path.join(self._block_update_dir, f"block_{file_id}.ini")
        if not os.path.exists(path):
            raise SystemBlocksError(f"板块文件不存在: {path}")
        try:
            text = Path(path).read_text(encoding="gbk", errors="replace")
        except OSError as exc:
            raise SystemBlocksError(f"读取板块文件失败: {path}: {exc}") from exc
        names, constituents = parse_block_ini(text)
        self._files[file_id] = (names, constituents)
        logger.info("系统板块：block_%s.ini 已加载（%d 个板块）",
                    file_id, max(0, len(names) - 1))
        return names, constituents

    # ── 分类发现 ──

    def categories(self) -> list[dict]:
        """返回板块分类列表（含行业），按树根顺序 + industry 优先。"""
        if self._categories is not None:
            return self._categories
        result: list[dict] = []
        try:
            names, constituents = self._load_industry()
            result.append({
                "id": "industry",
                "file_id": "industry.ini",
                "name": "行业(同花顺)",
                "source": "industry.ini",
                "board_count": len(names),
            })
        except SystemBlocksError as exc:
            logger.debug("industry.ini 不可用：%s", exc)

        tree = self._load_tree()
        group_ids = self._tree_group_ids(tree)
        for root_id, value in tree_root_children(tree).items():
            try:
                names, constituents = self._load_block_file(root_id)
            except SystemBlocksError as exc:
                logger.debug("跳过板块文件 %s：%s", root_id, exc)
                continue
            root_name = names.get(root_id, root_id)
            count = max(
                0,
                len([bid for bid in names if bid != root_id and bid not in group_ids]),
            )
            if count == 0 and not constituents:
                continue
            result.append({
                "id": _FILE_TO_ALIAS.get(root_id, root_id),
                "file_id": root_id,
                "name": root_name,
                "source": f"block_{root_id}.ini",
                "board_count": count,
            })
        self._categories = result
        return result

    def _resolve_file_id(self, category: str) -> str | None:
        key = category.strip().lower()
        if key == "industry":
            return "industry"
        if key in CATEGORY_ALIASES:
            return CATEGORY_ALIASES[key]
        upper = category.strip().upper()
        for cat in self.categories():
            if cat["file_id"].upper() == upper or str(cat["id"]).upper() == upper:
                return cat["file_id"]
        # 中文名匹配（如 “概念”“地域”）
        for cat in self.categories():
            if cat["name"] == category.strip() or category.strip() in str(cat["name"]):
                return cat["file_id"]
        return None

    # ── 板块列表 ──

    def boards(self, category: str | None = None) -> list[SystemBlock]:
        """列出系统板块。

        Args:
            category: None=全部分类；否则为分类键/文件 ID/中文名
                （如 ``concept``、``2B``、``概念``、``industry``）。

        Returns:
            板块列表，行业在前（881xxx），其余按板块文件顺序。
        """
        parents = self._parent_map()
        group_ids = self._tree_group_ids(self._load_tree())
        result: list[SystemBlock] = []
        if category is None:
            for cat in self.categories():
                result.extend(self.boards(cat["id"]))
            return result

        file_id = self._resolve_file_id(category)
        if file_id is None:
            raise SystemBlocksError(f"未知板块分类: {category}")
        if file_id == "industry":
            names, constituents = self._load_industry()
            for block_id in names:
                result.append(SystemBlock(
                    block_id=block_id,
                    name=names[block_id],
                    category="industry",
                    category_name="行业(同花顺)",
                    source="industry.ini",
                    parent_id=parents.get(block_id),
                ))
            return result

        names, constituents = self._load_block_file(file_id)
        cat = next(
            (c for c in self.categories() if c["file_id"] == file_id),
            {"id": file_id, "name": names.get(file_id, file_id)},
        )
        category_key = str(cat["id"])
        for block_id, name in names.items():
            if block_id == file_id or block_id in group_ids:
                continue  # 根节点/树分组（文件夹）不是板块
            result.append(SystemBlock(
                block_id=block_id,
                name=name,
                category=category_key,
                category_name=str(cat["name"]),
                source=f"block_{file_id}.ini",
                parent_id=parents.get(block_id),
            ))
        return result

    @staticmethod
    def _tree_group_ids(tree: dict[str, dict[str, str]]) -> set[str]:
        """树中 value 以 ``@`` 开头的 key 都是分组节点（文件夹）。"""
        groups: set[str] = set()
        for children in tree.values():
            for block_id, value in children.items():
                if value.startswith("@"):
                    groups.add(block_id)
        return groups

    def board(self, block_id: str) -> SystemBlock | None:
        """按稳定 ID 查板块（大小写不敏感）。"""
        block_id = normalize_block_id(block_id)
        for board in self.boards():
            if board.block_id == block_id:
                return board
        return None

    # ── 成分股 ──

    def constituents(self, block_id: str) -> list[BlockStock]:
        """返回板块成分股（只读，市场码按 hexin 数字码）。

        Args:
            block_id: 稳定 ID（``881121`` / ``C024`` …）。

        Returns:
            成分股列表；行业板块的市场码按代码前缀推断（17/33/-105），
            概念等板块保留文件中的市场码。

        Raises:
            SystemBlocksError: 板块 ID 不存在。
        """
        block_id = normalize_block_id(block_id)
        if block_id.isdigit() and block_id.startswith("881"):
            names, constituents = self._load_industry()
            codes = constituents.get(block_id)
            if codes is None:
                raise SystemBlocksError(f"行业板块不存在: {block_id}")
            return [
                BlockStock(code=code, market=infer_market_from_code(code) or "")
                for code in codes
            ]
        for cat in self.categories():
            file_id = cat["file_id"]
            if file_id == "industry.ini":
                continue
            names, constituents = self._load_block_file(file_id)
            if block_id in names:
                return list(constituents.get(block_id, ()))
        raise SystemBlocksError(f"板块不存在: {block_id}")

    def stock_boards(self, code: str) -> list[SystemBlock]:
        """反向查询：某只股票所属的全部系统板块（行业 + 概念等）。"""
        code = code.strip()
        result: list[SystemBlock] = []
        for board in self.boards():
            try:
                stocks = self.constituents(board.block_id)
            except SystemBlocksError:
                continue
            if any(s.code == code for s in stocks if not s.pattern):
                result.append(board)
        return result


class BoardService:
    """系统板块网络查询（MAIN 8901，板块指数 market=48）。

    2026-08-01 抓包确认：Level2 账号走 5716/6000/6002，普通账号走
    392/4180/4181；响应为 hd3.1 + BitRLE（0x130 板块行情、0x64 成分股、
    0x42 板块分时、0x32 板块竞价）。

    ⚠ 活网接线状态：板块查询需要**专用板块通道**（独立 8901 连接，先完成
    subreal 注册 + ``MarketCode=96;128;88;216;48;`` 初始化 + ``[5],[55]``
    分类表 + StockNameVer 引导）。实测在 MAIN 连接上直接发板块请求
    （含抓包原样帧）服务器不回数据，因此本类在通道接线完成前仅可用于
    已初始化通道的调用方。
    """

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 8,
        level2: bool | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._level2 = level2

    def _is_level2(self) -> bool:
        if self._level2 is not None:
            return self._level2
        return self._connections.profile.kind is AccountKind.LEVEL2

    def _request(
        self,
        request: bytes,
        *,
        parsers: tuple[Callable[[bytes], list[dict]], ...],
        timeout: float = 12.0,
    ) -> list[dict]:
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )
        try:
            with connection.request(request, timeout=timeout) as sock:
                for _ in range(self._max_frames):
                    response = self._read_frame(sock)
                    for parser in parsers:
                        records = parser(response)
                        if records:
                            return records
        except (socket.timeout, OSError) as exc:
            raise ProtocolError(f"板块查询超时/网络错误: {exc}") from exc
        return []

    def board_quotes(
        self,
        codes: list[str],
        *,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块指数行情列表（含名称/最新价/量额，0x130 表）。"""
        request = build_board_list_query(codes, level2=self._is_level2())
        return self._request(
            request,
            parsers=(parse_board_quote_response,),
            timeout=timeout,
        )

    def board_timeline(
        self,
        code: str,
        date=None,
        *,
        timeout: float = 12.0,
    ) -> list[dict]:
        """板块指数当日/历史分时（0x42 表，242 点/日）。"""
        request = build_board_timeline_query(
            code,
            date=date,
            level2=self._is_level2(),
        )
        return self._request(
            request,
            parsers=(parse_board_timeline_response,),
            timeout=timeout,
        )

    def board_auction(
        self,
        code: str,
        date=None,
        *,
        timeout: float = 12.0,
    ) -> list[dict]:
        """板块指数集合竞价（0x32 表）。"""
        request = build_board_auction_query(
            code,
            date=date,
            level2=self._is_level2(),
        )
        return self._request(
            request,
            parsers=(parse_board_auction_response,),
            timeout=timeout,
        )

    def board_constituents(
        self,
        codes: list[str],
        *,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块成分股行情（0x64 表）。"""
        request = build_board_constituents_query(
            codes,
            level2=self._is_level2(),
        )
        return self._request(
            request,
            parsers=(parse_board_constituents_response,),
            timeout=timeout,
        )


__all__ = [
    "CATEGORY_ALIASES",
    "BoardService",
    "SystemBlocksError",
    "SystemBlocksService",
    "default_hexin_dir",
]
