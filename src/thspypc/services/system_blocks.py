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
import time
import datetime as dt
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
    build_board_constituents_page_transition,
    build_board_constituents_selection_query,
    build_board_constituents_sort_query,
    build_board_list_query,
    build_board_timeline_query,
    parse_board_auction_response,
    parse_board_constituents_response,
    parse_board_constituents_selection_response,
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


def _coerce_trade_date(value) -> dt.date:
    if value is None:
        return dt.date.today()
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    return dt.date.fromisoformat(str(value))


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
    """系统板块网络查询（专用板块通道 fu4 8901，板块指数 market=48）。

    2026-08-01 抓包确认：Level2 账号走 5716/6000/6002，普通账号走
    392/4180/4181；响应为 hd3.1 + BitRLE（0x130 板块行情、0x64 成分股、
    0x42 板块分时、0x32 板块竞价）。

    ★ 活网接线（2026-08-01）：板块查询需要**专用板块通道**（独立 8901 连接，
    走 fu4.123ths.com 服务器组：login（Level2 无用户名 / 普通 __manual）→
    subreal 注册 → ``MarketCode=96;128;88;216;48;`` 初始化 → qureal-init×10 →
    ``[5],[55]`` 分类表 → StockNameVer 引导）。实测在 MAIN 连接上直接发板块
    请求（含抓包原样帧）服务器不回数据；建连/引导由
    ``_open_board_channel`` 负责，本服务经 ``ConnectionRole.BOARD`` 取通道。
    """

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 64,
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
        accept: Callable[[list[dict]], bool] | None = None,
        role: ConnectionRole = ConnectionRole.BOARD,
    ) -> list[dict]:
        connection = self._connections.acquire(
            role,
            capability=Capability.BASIC_QUOTE,
        )
        try:
            # pcap 原始流确认：板块 login、引导和业务请求的每个 FD 帧后均有
            # 0x0a 分隔符。此前按 MAGIC 切帧的工具丢掉了这些间隔，产生过
            # “请求无尾部换行”的错误结论。
            with connection.request(
                request,
                timeout=timeout,
                trailing_newline=True,
            ) as sock:
                deadline = time.monotonic() + timeout
                for _ in range(self._max_frames):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    response = self._read_frame(sock)
                    for parser in parsers:
                        records = parser(response)
                        if records and (accept is None or accept(records)):
                            return records
        except socket.timeout:
            return []
        except OSError as exc:
            raise ProtocolError(f"板块查询网络错误: {exc}") from exc
        return []

    def _request_sequence(
        self,
        requests: tuple[bytes, ...],
        *,
        parsers: tuple[Callable[[bytes], list[dict]], ...],
        timeout: float,
        accept: Callable[[list[dict]], bool] | None = None,
        interval: float = 0.04,
        role: ConnectionRole = ConnectionRole.BOARD,
    ) -> list[dict]:
        """在同一 BOARD socket 上连续发送一个页面事务后统一收响应。

        普通账号 4180 抓包中 Sort、527527 选择确认、完整行情三帧的发送间隔
        约 30--40ms，客户端不会逐帧等待响应。服务端也可能在事务补齐前保持
        静默，因此不能用三次 :meth:`_request` 串行编排。
        """
        if not requests:
            return []
        connection = self._connections.acquire(
            role,
            capability=Capability.BASIC_QUOTE,
        )
        try:
            with connection.request(
                requests[0],
                timeout=timeout,
                trailing_newline=True,
            ) as sock:
                for request in requests[1:]:
                    if interval > 0:
                        time.sleep(interval)
                    sock.sendall(request + b"\n")
                deadline = time.monotonic() + timeout
                for _ in range(self._max_frames):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    response = self._read_frame(sock)
                    for parser in parsers:
                        records = parser(response)
                        if records and (accept is None or accept(records)):
                            return records
        except socket.timeout:
            return []
        except OSError as exc:
            raise ProtocolError(f"板块查询网络错误: {exc}") from exc
        return []

    def board_quotes(
        self,
        codes: list[str],
        *,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块指数行情列表（含名称/最新价/量额，0x130 表）。"""
        request = build_board_list_query(codes, level2=self._is_level2())
        wanted_codes = set(codes)
        return self._request(
            request,
            parsers=(parse_board_quote_response,),
            timeout=timeout,
            accept=lambda records: any(
                record.get("code") in wanted_codes for record in records
            ),
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
        expected_date = _coerce_trade_date(date)
        records = self._request(
            request,
            parsers=(parse_board_timeline_response,),
            timeout=timeout,
            accept=lambda records: any(
                record.get("date") == expected_date for record in records
            ),
        )
        matched = [
            record for record in records
            if record.get("date") == expected_date
        ]
        # 0x42 首行是该日基准价哨兵，dt1 不是 packed-date；保留并显式归属
        # 到目标日期，避免显示成伪造的远期年份。
        if records and "date" not in records[0] and matched:
            baseline = dict(records[0])
            baseline["date"] = expected_date
            baseline["is_baseline"] = True
            return [baseline, *matched]
        return matched

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
        expected_date = _coerce_trade_date(date)
        records = self._request(
            request,
            parsers=(parse_board_auction_response,),
            timeout=timeout,
            accept=lambda records: any(
                getattr(record.get("time"), "date", lambda: None)()
                == expected_date
                for record in records
            ),
        )
        start = dt.time(9, 15)
        end = dt.time(9, 25)
        return [
            record for record in records
            if (
                isinstance(record.get("time"), dt.datetime)
                and record["time"].date() == expected_date
                and start <= record["time"].time() <= end
            )
        ]

    def board_constituents(
        self,
        stock_codes: list[str],
        *,
        stock_markets: dict[str, int | str] | None = None,
        timeout: float = 40.0,
    ) -> list[dict]:
        """对已展开的成分股代码批量查询行情（0x64 表）。"""
        records: list[dict] = []
        returned_codes: set[str] = set()
        deadline = time.monotonic() + timeout
        if self._is_level2():
            # L2 页面提交整个板块 universe，并按沪/深市场拆到两个等价的
            # 页面组件连接。服务层可在同一连接上顺序发两个完整市场批次；
            # 按首屏 21 股切块不是抓包中的协议，服务端会静默忽略。
            groups: tuple[list[str], ...] = (
                [
                    code for code in stock_codes
                    if str((stock_markets or {}).get(code, "")) != "33"
                    and not code.startswith(("0", "1", "2", "3"))
                ],
                [
                    code for code in stock_codes
                    if str((stock_markets or {}).get(code, "")) == "33"
                    or code.startswith(("0", "1", "2", "3"))
                ],
            )
            for group_index, batch in enumerate(groups):
                if not batch:
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                request = build_board_constituents_query(
                    batch,
                    level2=True,
                    seq=0x1082 + group_index,
                    route_base=0x005C,
                    markets=stock_markets,
                    visible_codes=batch[:21],
                    context_market=16 if group_index == 0 else 32,
                )
                wanted_codes = set(batch)
                role = (
                    ConnectionRole.BOARD_CONSTITUENT_SH
                    if group_index == 0
                    else ConnectionRole.BOARD_CONSTITUENT_SZ
                )
                if group_index == 0:
                    page_records = self._request_sequence(
                        (
                            build_board_constituents_page_transition(True),
                            request,
                        ),
                        parsers=(parse_board_constituents_response,),
                        timeout=remaining,
                        accept=lambda result, wanted=wanted_codes: any(
                            record.get("code") in wanted for record in result
                        ),
                        interval=0.0,
                        role=role,
                    )
                else:
                    page_records = self._request(
                        request,
                        parsers=(parse_board_constituents_response,),
                        timeout=remaining,
                        accept=lambda result, wanted=wanted_codes: any(
                            record.get("code") in wanted for record in result
                        ),
                        role=role,
                    )
                for record in page_records:
                    code = str(record.get("code", ""))
                    if code and code not in returned_codes:
                        returned_codes.add(code)
                        records.append(record)
            return records

        # 普通账号先等待 Sort 返回服务端选出的代码页，再用这些代码发送
        # 527527 和完整行情。新包明确显示 Sort 与后两帧之间存在响应边界，
        # 不能再拿本地 membership 顺序猜服务端排序页。
        page_size = 22
        universe = set(stock_codes)
        for begin in range(0, len(stock_codes), page_size):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sort_request = build_board_constituents_sort_query(
                stock_codes,
                visible_codes=stock_codes[begin: begin + page_size],
                sort_begin=begin,
                sort_count=page_size,
                seq=0x10A7 + begin,
                route_base=0x0044,
                markets=stock_markets,
            )
            sort_requests = (sort_request,)
            if begin == 0:
                sort_requests = (
                    build_board_constituents_page_transition(False),
                    sort_request,
                )
            sorted_page = self._request_sequence(
                sort_requests,
                parsers=(parse_board_constituents_selection_response,),
                timeout=remaining,
                accept=lambda result: any(
                    str(record.get("code", "")) in universe
                    for record in result
                ),
                interval=0.0,
                role=ConnectionRole.BOARD_CONSTITUENT_SH,
            )
            page_codes = list(dict.fromkeys(
                str(record.get("code", ""))
                for record in sorted_page
                if str(record.get("code", "")) in universe
            ))
            if not page_codes:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            selection_request = build_board_constituents_selection_query(
                page_codes,
                seq=0x10AB + begin,
                route_base=0x0044,
                markets=stock_markets,
            )
            quote_request = build_board_constituents_query(
                page_codes,
                level2=False,
                seq=0x10AD + begin,
                include_prefix=False,
                route_base=0x0044,
                markets=stock_markets,
            )
            wanted_codes = set(page_codes)
            page_records = self._request_sequence(
                (selection_request, quote_request),
                parsers=(parse_board_constituents_response,),
                timeout=remaining,
                accept=lambda result, wanted=wanted_codes: any(
                    record.get("code") in wanted for record in result
                ),
                interval=0.0,
                role=ConnectionRole.BOARD_CONSTITUENT_SH,
            )
            for record in page_records:
                code = str(record.get("code", ""))
                if code and code not in returned_codes:
                    returned_codes.add(code)
                    records.append(record)
            if len(page_codes) < page_size:
                break
        return records


__all__ = [
    "CATEGORY_ALIASES",
    "BoardService",
    "SystemBlocksError",
    "SystemBlocksService",
    "default_hexin_dir",
]
