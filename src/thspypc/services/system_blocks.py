"""系统板块只读服务（行业/概念/地域/港股…）。

数据源为 hexin PC 安装目录下的 ``BlockUpdate/block_*.ini`` 与
``industry.ini``（本地 block_hq 缓存域）；本机没有 hexin 目录时，首次使用
会自动从 ``cloud.10jqka.com.cn`` 全量下载板块 ZIP 到用户缓存目录。

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
import re
import socket
import threading
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
    build_board_full_list_query,
    build_board_hot_query,
    build_board_hot_sort_query,
    build_board_kline_query,
    build_board_list_query,
    build_board_timeline_query,
    load_board_full_codes,
    parse_board_auction_response,
    parse_board_constituents_response,
    parse_board_constituents_selection_response,
    parse_board_full_quote_response,
    parse_board_hot_detail_response,
    parse_board_hot_sort_response,
    parse_board_timeline_response,
)
from ..features.kline_protocol import parse_kline_hd3_response
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


_BLOCKUPDATE_CACHE_DIR = os.path.join(
    os.path.expanduser("~"), ".thspypc", "blockupdate"
)
_BLOCKUPDATE_LOCK = threading.Lock()
_BLOCKUPDATE_REFRESH_RUNNING = False
_BLOCK_FILE_RE = re.compile(r"^block_[0-9A-F]+\.ini$", re.IGNORECASE)


def _blockupdate_has_files(block_update_dir: str) -> bool:
    """目录中至少存在一个云同步包会提供的 block_*.ini。"""
    try:
        names = os.listdir(block_update_dir)
    except OSError:
        return False
    return any(_BLOCK_FILE_RE.match(name) for name in names)


def _synthesize_block_tree(block_update_dir: str) -> None:
    """缓存目录缺少 block_tree.ini 时生成扁平板块树兜底。

    当前云 ZIP 已包含 ``block_tree.ini``；此函数仅用于旧缓存/手工缓存目录
    只有 ``block_*.ini`` 的场景。扁平树把所有文件作为根分类，足以支撑
    分类发现和名称映射。
    """
    tree_path = os.path.join(block_update_dir, "block_tree.ini")
    if os.path.exists(tree_path):
        return
    file_ids = sorted(
        name[6:-4]
        for name in os.listdir(block_update_dir)
        if _BLOCK_FILE_RE.match(name)
    )
    lines = [
        "[ConfigInfo]",
        "ConfigName=stockblock_cloud",
        "ConfigVer=0",
        "",
        "[BLOCK_TREE_ROOT]",
        "1=@10001",
        "",
        "[@10001]",
    ]
    lines.extend(f"{file_id}={idx + 1}" for idx, file_id in enumerate(file_ids))
    Path(tree_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _install_cloud_block_zip(zip_bytes: bytes, block_update_dir: str) -> None:
    """解压 cloud.10jqka.com.cn 的系统板块 ZIP 到缓存目录。"""
    import io
    import zipfile

    from ..features import blockupdate_cloud as cloud

    manifest = cloud.parse_block_zip(zip_bytes)
    if not manifest.files:
        raise SystemBlocksError("系统板块云同步 ZIP 中没有 block_*.ini")

    os.makedirs(block_update_dir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(manifest.raw)) as zf:
        for entry in manifest.files:
            name = os.path.basename(entry.name)
            if name != "block_tree.ini" and not _BLOCK_FILE_RE.match(name):
                raise SystemBlocksError(f"系统板块云同步包含异常文件名: {entry.name}")
            data = zf.read(entry.name)
            tmp_path = os.path.join(block_update_dir, name + ".tmp")
            with open(tmp_path, "wb") as f:
                f.write(data)
            os.replace(tmp_path, os.path.join(block_update_dir, name))

    entries_dir = os.path.join(block_update_dir, "__base_")
    os.makedirs(entries_dir, exist_ok=True)
    Path(os.path.join(entries_dir, "_entries")).write_text(
        cloud.build_entries_text(manifest), encoding="utf-8"
    )
    _synthesize_block_tree(block_update_dir)
    logger.info(
        "系统板块云同步完成：%s（version=%s, files=%d）",
        block_update_dir, manifest.max_version, len(manifest.files),
    )


def _bundled_blockupdate_dir() -> str | None:
    """仓库内置的 BlockUpdate 基线（仅本仓库开发环境可用）。"""
    repo_root = Path(__file__).resolve().parents[3]
    bundled = repo_root / "tests" / "fixtures" / "blockupdate" / "204655"
    return str(bundled) if bundled.is_dir() else None


def _blockupdate_entries_dir(block_update_dir: str) -> str:
    return os.path.join(block_update_dir, "__base_")


def _blockupdate_checked_marker(block_update_dir: str) -> str:
    return os.path.join(_blockupdate_entries_dir(block_update_dir), "_last_checked")


def _blockupdate_checked_today(block_update_dir: str) -> bool:
    """板块云同步是否今天已检查过（与股票缓存同样的自然日策略）。"""
    marker = _blockupdate_checked_marker(block_update_dir)
    try:
        written = dt.date.fromtimestamp(os.path.getmtime(marker))
    except OSError:
        return False
    return written == dt.date.today()


def _mark_blockupdate_checked(block_update_dir: str) -> None:
    try:
        entries_dir = _blockupdate_entries_dir(block_update_dir)
        os.makedirs(entries_dir, exist_ok=True)
        Path(_blockupdate_checked_marker(block_update_dir)).write_text(
            dt.date.today().isoformat(), encoding="ascii"
        )
    except OSError as exc:
        logger.debug("无法写入板块更新检查标记：%s", exc)


def _local_blockupdate_version(block_update_dir: str) -> int:
    """读取 __base_/_entries 的 system.version，读不到按 0 触发全量。"""
    entries_path = os.path.join(_blockupdate_entries_dir(block_update_dir), "_entries")
    try:
        text = Path(entries_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("version="):
            try:
                return int(line.split("=", 1)[1])
            except ValueError:
                return 0
    return 0


def _refresh_cloud_blockupdate_cache(block_update_dir: str) -> bool:
    """按本地版本请求云 ZIP；无更新返回 True，失败时保留旧缓存。"""
    from ..features import blockupdate_cloud as cloud

    version = _local_blockupdate_version(block_update_dir)
    try:
        zip_bytes = cloud.fetch_block_zip(version, timeout=15)
        _install_cloud_block_zip(zip_bytes, block_update_dir)
    except cloud.BlockCloudUpToDate:
        logger.info("系统板块缓存已是最新（version=%s）", version)
    except Exception as exc:
        logger.warning("系统板块云更新失败，继续使用本地缓存：%s", exc)
        return False
    _mark_blockupdate_checked(block_update_dir)
    return True


def _start_background_blockupdate_refresh(cache_dir: str) -> None:
    """把每日版本检查放到后台，避免首个 /api/boards 阻塞在云请求上。"""
    global _BLOCKUPDATE_REFRESH_RUNNING
    if _BLOCKUPDATE_REFRESH_RUNNING:
        return
    _BLOCKUPDATE_REFRESH_RUNNING = True

    def run() -> None:
        global _BLOCKUPDATE_REFRESH_RUNNING
        try:
            # 先让当前进程用旧缓存完成首屏加载，再开始网络检查。
            time.sleep(0.5)
            _refresh_cloud_blockupdate_cache(cache_dir)
        finally:
            _BLOCKUPDATE_REFRESH_RUNNING = False

    threading.Thread(
        target=run,
        name="ths-blockupdate-refresh",
        daemon=True,
    ).start()


def _ensure_cloud_blockupdate_cache() -> str:
    """首次使用全量拉取板块 ZIP，之后按自然日在后台做版本检查更新。"""
    cache_dir = os.environ.get(
        "THS_BLOCKUPDATE_CACHE_DIR", _BLOCKUPDATE_CACHE_DIR
    )
    with _BLOCKUPDATE_LOCK:
        if _blockupdate_has_files(cache_dir):
            _synthesize_block_tree(cache_dir)
            if not _blockupdate_checked_today(cache_dir):
                _start_background_blockupdate_refresh(cache_dir)
            return cache_dir
        try:
            from ..features import blockupdate_cloud as cloud

            zip_bytes = cloud.fetch_block_zip(0, timeout=15)
            _install_cloud_block_zip(zip_bytes, cache_dir)
            _mark_blockupdate_checked(cache_dir)
            return cache_dir
        except Exception as exc:
            bundled = _bundled_blockupdate_dir()
            if bundled is not None and _blockupdate_has_files(bundled):
                logger.warning(
                    "系统板块云同步失败，回退到仓库内置基线 %s（%s）",
                    bundled, exc,
                )
                return bundled
            raise SystemBlocksError(
                "未找到本地 BlockUpdate，且系统板块云同步失败："
                f"{type(exc).__name__}: {exc}"
            ) from exc


def _resolve_blockupdate_dir(local_hexin: str | None) -> str:
    """按本地 hexin 目录优先，缺失时回退到云同步缓存。"""
    if local_hexin:
        candidate = os.path.join(local_hexin, "BlockUpdate")
        if os.path.isdir(candidate) and _blockupdate_has_files(candidate):
            return candidate
    return _ensure_cloud_blockupdate_cache()


class SystemBlocksService:
    """系统板块只读服务，进程内按需加载并缓存解析结果。"""

    def __init__(
        self,
        hexin_dir: str | None = None,
        *,
        block_update_dir: str | None = None,
    ) -> None:
        local_hexin = hexin_dir or default_hexin_dir()
        if block_update_dir is None:
            block_update_dir = os.environ.get("THS_BLOCKUPDATE_DIR") or None
        if block_update_dir is None:
            block_update_dir = _resolve_blockupdate_dir(local_hexin)
        self._hexin_dir = local_hexin
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
        codes: list[str] | None = None,
        *,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块指数行情列表。

        ``codes=None`` 时发送**全量请求**：一次携带抓包确认的 513 个板块
        指数代码（DataType=527527；响应为 0x20/0x1c/0x22 紧凑表，跨帧
        到达），返回按代码合并后的全部板块行情，可直接用于本地表头排序
        与分页。板块资金流按 PC 版口径即**累计主力净流入**
        （``main_inflow``/dt250，无分时资金流曲线），已包含在返回记录中。
        显式传 codes 时走列表查询（0x130 名称行情表请求；08-02 起服务端对
        同一请求回 0x20/0x1c/0x22 紧凑表，无名称列），查询子帧携带完整
        universe（对齐抓包），返回时按请求的 codes 过滤。
        """
        if codes is None:
            codes = list(load_board_full_codes())
            level2 = self._is_level2()
            requests = (
                # 列表订阅：0x20（昨收/最新/4分钟涨速）+ 0x1c（主力金额）
                build_board_list_query(codes, level2=level2),
                # 527527 全量：0x22（1分钟涨速，513×3 行）
                build_board_full_list_query(codes, level2=level2),
            )
            return self._request_full_quotes(
                requests, codes, timeout=timeout
            )
        request = build_board_list_query(
            codes,
            level2=self._is_level2(),
            universe_codes=list(load_board_full_codes()),
        )
        wanted_codes = set(codes)
        records = self._request(
            request,
            parsers=(parse_board_full_quote_response,),
            timeout=timeout,
            accept=lambda records: any(
                record.get("code") in wanted_codes for record in records
            ),
        )
        return [
            record for record in records
            if str(record.get("code", "")) in wanted_codes
        ]

    def hot_boards(
        self,
        codes: list[str] | None = None,
        *,
        timeout: float = 15.0,
    ) -> list[dict]:
        """热点板块（94 页面）行情，pageid=12480。

        2026-08-07 双账号抓包（kanpan_20260807_224017.pcap Level2 /
        kanpan_20260807_225319.pcap 普通 / kanpan_20260807_231038.pcap 排序）
        确认：热点板块与板块列表（392/5716）共用同一批 fu4 板块通道连接，
        请求为同构双子帧，仅组件路由不同（普通 0x003A/0x013A、L2
        0x0053/0x0153）。

        ``codes=None`` 时在同一 BOARD socket 连续发送两个请求并跨帧合并：
        - **详情请求**（DataType=271,...）：0x40/72B 表，含
          ``pre_close``/``price``/``chg_pct``（dt6/dt10）、``limit_up``
          （dt15 涨停数）、``up_count``（dt38 涨家数）、``down_count``
          （dt39 跌家数）、``speed_4m``（dt48 4分钟涨速）；
        - **527527 全量请求**（DateTime=8192(-2-0)）：0x22 1分钟涨速
          （dt167 ``speed_1m``）、0x1c 主力净流入（dt250 ``main_inflow``）。

        885927 CRO概念 实测对照（2026-08-07）：chg +8.05%、涨停 8、
        涨家 73、跌家 3、4分钟涨速 -0.00% 与 94 页面 UI 一致。

        显式传 ``codes`` 时只发详情请求（单请求，轻量）。表头排序见
        :meth:`hot_boards_sorted`。
        """
        if codes is None:
            codes = list(load_board_full_codes())
        wanted_codes = set(codes)
        level2 = self._is_level2()
        detail_request = build_board_hot_query(
            codes,
            level2=level2,
            lack_time="0,0,0,0,0,0,0,0",
        )
        if len(codes) < 60:
            # 显式/小批量：单个详情请求
            records = self._request(
                detail_request,
                parsers=(
                    parse_board_hot_detail_response,
                    parse_board_full_quote_response,
                ),
                timeout=timeout,
                accept=lambda records: any(
                    record.get("code") in wanted_codes for record in records
                ),
            )
            return [
                record for record in records
                if str(record.get("code", "")) in wanted_codes
            ]
        # 全量：详情 + 527527 全量 合并（与 board_quotes(None) 同构）。
        # 抓包（kanpan_20260807_231038.pcap 帧920）hot 的 527527 请求是
        # DateTime=0(0-0)、LackTime 全 0（区别于 board_quotes 的 8192(-2-0)）。
        full_request = build_board_hot_query(
            codes,
            level2=level2,
            datatype=[527527],
            period=0,
            args="0-0",
            history_flag=False,
            lack_time="0,0,0,0,0,0,0,0",
        )
        inflow_request = build_board_hot_query(
            codes,
            level2=level2,
            datatype=[592890],
            period=0,
            args="0-0",
            history_flag=False,
            lack_time="0,0,0,0,0,0,0,0",
        )
        return self._request_hot_full(
            (detail_request, full_request, inflow_request),
            codes,
            timeout=timeout,
        )

    def _request_hot_full(
        self,
        requests: tuple[bytes, ...],
        wanted_codes: list[str],
        *,
        timeout: float,
    ) -> list[dict]:
        """发送热点板块全量请求序列并跨帧合并详情(0x40) + 全量(0x20/0x1c/0x22)。"""
        if not requests:
            return []
        connection = self._connections.acquire(
            ConnectionRole.BOARD,
            capability=Capability.BASIC_QUOTE,
        )
        wanted = set(wanted_codes)
        try:
            with connection.request(
                requests[0],
                timeout=timeout,
                trailing_newline=True,
            ) as sock:
                for request in requests[1:]:
                    time.sleep(0.04)
                    sock.sendall(request + b"\n")
                deadline = time.monotonic() + timeout
                merged: dict[str, dict] = {}
                for _ in range(self._max_frames):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    try:
                        response = self._read_frame(sock)
                    except socket.timeout:
                        break
                    for parser in (
                        parse_board_hot_detail_response,
                        parse_board_full_quote_response,
                    ):
                        for rec in parser(response):
                            code = str(rec.get("code", ""))
                            if not code:
                                continue
                            target = merged.setdefault(code, {"code": code})
                            for key, value in rec.items():
                                if key != "code" and (
                                    key not in target or target[key] is None
                                ):
                                    target[key] = value
                    have_detail = sum(
                        1 for r in merged.values() if "up_count" in r
                    )
                    have_speed_1m = sum(
                        1 for r in merged.values() if "dt167" in r
                    )
                    have_main = sum(
                        1 for r in merged.values() if "dt250" in r
                    )
                    if (
                        len(merged) >= len(wanted)
                        and have_detail >= len(wanted) - 10
                        and have_speed_1m >= len(wanted) - 10
                        and have_main >= len(wanted) - 10
                    ):
                        break
        except OSError as exc:
            raise ProtocolError(f"板块查询网络错误: {exc}") from exc
        return [merged[code] for code in wanted_codes if code in merged]

    def hot_boards_sorted(
        self,
        sort_by: int,
        *,
        codes: list[str] | None = None,
        sort_dir: str = "D",
        sort_begin: int = 0,
        sort_count: int = 26,
        timeout: float = 15.0,
    ) -> list[dict]:
        """热点板块表头排序，返回按列排序后的 (code, value) 记录。

        ``sort_by`` 取值见 :data:`HOT_SORT_BY_*`。服务端响应 ``method=sort``
        + hd3.1 表（dt5 代码 + **dt<SortBy>** 排序字段值，SortBy 即响应第二
        字段的 dt 编号）：
        - ``HOT_SORT_BY_CHG``(199112) → dt200 涨跌幅（ZHANGDIEFU）
        - ``HOT_SORT_BY_SPEED_1M``(527527) → dt167 1分钟涨速（onerise）
        - ``HOT_SORT_BY_MAIN_INFLOW``(592890) → dt250 主力净流入
        - ``HOT_SORT_BY_LIMIT_UP``(271) → dt15 涨停数
        - ``HOT_SORT_BY_UP_COUNT``(38)/``HOT_SORT_BY_DOWN_COUNT``(39)
          → dt38/dt39 涨跌家数

        Returns:
            list[dict]，按排序序，每条含 ``code`` + ``value``（排序字段
            THS float 值，语义随 sort_by：涨跌幅/涨速为百分比，主力为元，
            涨停/涨跌家为个数）+ ``dt<SortBy>`` 原始键。
        """
        if codes is None:
            codes = list(load_board_full_codes())
        request = build_board_hot_sort_query(
            codes,
            sort_by=sort_by,
            sort_dir=sort_dir,
            sort_begin=sort_begin,
            sort_count=sort_count,
            level2=self._is_level2(),
        )
        records = self._request(
            request,
            parsers=(parse_board_hot_sort_response,),
            timeout=timeout,
            accept=lambda records: bool(records),
        )
        return [
            {
                "code": str(record.get("code", "")),
                "value": record.get("value"),
                **{
                    key: value
                    for key, value in record.items()
                    if key.startswith("dt")
                },
            }
            for record in records
            if record.get("code")
        ]

    def _request_full_quotes(
        self,
        requests: tuple[bytes, ...],
        wanted_codes: list[str],
        *,
        timeout: float,
    ) -> list[dict]:
        """发送全量行情请求序列并跨帧合并三类响应表。

        2026-08-02 抓包：客户端先发**列表订阅**请求（DataType=48,592890,
        10,6,66，返回 0x20 昨收/最新/4分钟涨速 + 0x1c 主力金额），再发
        **527527** 全量请求（返回 0x22 1分钟涨速，513×3 行）。两类请求
        在同一 BOARD socket 上连续发送，响应按帧累积合并；超时/帧数耗尽
        时返回已合并的部分记录。哨兵字段由解析器映射为 None（UI 显示“-”）。
        """
        if not requests:
            return []
        connection = self._connections.acquire(
            ConnectionRole.BOARD,
            capability=Capability.BASIC_QUOTE,
        )
        wanted = set(wanted_codes)
        try:
            with connection.request(
                requests[0],
                timeout=timeout,
                trailing_newline=True,
            ) as sock:
                for request in requests[1:]:
                    time.sleep(0.04)
                    sock.sendall(request + b"\n")
                deadline = time.monotonic() + timeout
                merged: dict[str, dict] = {}
                for _ in range(self._max_frames):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    try:
                        response = self._read_frame(sock)
                    except socket.timeout:
                        break
                    for rec in parse_board_full_quote_response(response):
                        code = str(rec.get("code", ""))
                        if not code:
                            continue
                        target = merged.setdefault(code, {"code": code})
                        for key, value in rec.items():
                            # 缺键或原值为 None（该帧未携带/哨兵）时写入；
                            # 真实值会覆盖此前帧的 None。
                            if key != "code" and (
                                key not in target or target[key] is None
                            ):
                                target[key] = value
                    have_base = sum(
                        1 for r in merged.values()
                        if "dt6" in r and "dt10" in r
                    )
                    have_speed_1m = sum(
                        1 for r in merged.values() if "dt167" in r
                    )
                    have_main = sum(
                        1 for r in merged.values() if "dt250" in r
                    )
                    if (
                        len(merged) >= len(wanted)
                        and have_base >= len(wanted) - 10
                        and have_speed_1m >= len(wanted) - 10
                        and have_main >= len(wanted) - 10
                    ):
                        break
        except OSError as exc:
            raise ProtocolError(f"板块查询网络错误: {exc}") from exc
        return [merged[code] for code in wanted_codes if code in merged]

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

    def board_kline(
        self,
        code: str,
        *,
        fuquan: str = "Q",
        count: int = 2146,
        anchor: int = 0,
        timeout: float = 12.0,
    ) -> list[dict]:
        """板块指数日K（period=16384，响应 0x42 日K 表）。

        ``DateTime=16384(-{count}-{anchor})`` 语义与股票日K 一致：取
        ``count`` 根、以 ``anchor``（YYYYMMDD，0=最新）为终点，服务端返回
        ``count+1`` 根（受板块发布日截断）。响应为 0x42 表（字段
        [1,7,8,9,11,19,13]，dt1=YYYYMMDD），由
        :func:`parse_kline_hd3_response` 解析为 ``time``/``open``/``high``/
        ``low``/``close``/``volume``/``amount`` 记录。
        """
        request = build_board_kline_query(
            code,
            level2=self._is_level2(),
            fuquan=fuquan,
            count=count,
            anchor=anchor,
        )
        records = self._request(
            request,
            parsers=(parse_kline_hd3_response,),
            timeout=timeout,
            accept=lambda records: any(
                record.get("time") is not None for record in records
            ),
        )
        return [record for record in records if record.get("time") is not None]

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
