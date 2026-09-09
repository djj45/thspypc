"""Public market-data facade methods backed by services."""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import date as date_type, datetime, time as time_type, timedelta, timezone

from ..errors import ChannelUnavailableError, ProtocolError
from ..models import AccountKind, Capability, DepthQuote
from ..features.superorder_protocol import (
    SNAPSHOT_REPLAY_HIST_PAGEID,
    SNAPSHOT_REPLAY_INDEX_PAGEID,
    SNAPSHOT_REPLAY_PAGEID,
)
from ..protocol import LIST_QUOTE_DATATYPE_DEFAULT, pick_l2_market
from ..features.auth_protocol import LoginIdentity
from ..features.stock_name_bootstrap import STOCK_NAME_GROUPS, name_group_login_identity
from ..features.trade_calendar import latest_trade_date
from ..features.list_subscription_protocol import (
    RANKING_LIST_COMMAND,
    RANKING_LIST_DATATYPE,
    RANKING_LIST_PAGEID,
)
from ..services.stock_name import download_all_stock_names
from ..transport import ConnectionRole
from .stock_cache import (
    default_stock_cache_path,
    load_stock_codes,
    market_from_code,
    save_stock_codes,
)

logger = logging.getLogger(__name__)

# MAIN 通道串行锁：quotes_ext（多个面板并发）与盘口 market_view_pipeline 同跑
# 在一条 MAIN socket 上时，Windows 下并发读写会触发 WSAEWOULDBLOCK(10035)/
# 10038 传输异常，空结果又各自引发 connect_main 重连风暴，部分批次彻底失败
# （2026-08-19 日志实证：4 组并发批次全挂，前端对应行永远 "-"）。两类入口在
# facade 层串行化，消除争抢；单批 ~100ms，排队代价可忽略。
_MAIN_SERIAL_LOCK = threading.RLock()


def _intraday_market(market: int) -> int:
    """Map quote-only board markets to the base L2 intraday market.

    Shanghai ST quotes use the dedicated CodeList market 22, but the
    4214/4417 auction and history-timeline protocols still run on SH_L2 with
    market 17.  Passing 22 into AuctionService is therefore always invalid.
    """
    return 17 if market == 22 else market


class ServiceFacade:
    """Service-backed public methods shared by the compatibility client."""

    def stock_list_cached(
        self,
        *,
        cache_path: str | None = None,
        refresh: bool = False,
        with_names: bool = True,
        timeout: float = 30.0,
    ) -> list[dict]:
        """获取全市场股票代码表（带本地缓存，有效期一天=自然日）。

        :meth:`stock_list` 的缓存版：当天首次调用走网络拉取（~6s）并写盘，
        之后当天再调用直接读缓存（~瞬时），不再发网络请求。跨自然日自动失效。

        缓存文件 ``~/.ths_stock_codes.json``（见 :func:`default_stock_cache_path`），
        含全量代码 + 名称 + 派生市场码（沪=17/深=33），可直接喂给
        :meth:`list_quotes`。

        Args:
            cache_path: 缓存文件路径，None 用默认路径。
            refresh: True 时强制刷新（忽略缓存，重新走网络拉取并覆盖写盘）。
            with_names: 网络拉取时是否填充名称。默认 True（缓存场景几乎都要名称，
                且只写盘一次）。缓存命中时此参数无效（名称已存盘）。
            timeout: 网络拉取的总超时（秒），传给 :meth:`stock_list`。

        Returns:
            list[dict]，每项 ``{"code", "name", "market"}``，约 7400 条。
            market 为派生值：17=沪市 A 股、33=深市 A 股、None=北交所/新三板/基金
            （list_quotes 当前不支持的市场，仍保留 code+name 供其他用途）。

        Raises:
            RuntimeError: 未登录（缓存未命中需走网络时）。
        """
        path = cache_path or default_stock_cache_path()

        def fill_names(stocks: list[dict]) -> int:
            """用当日名称组缓存/网络补全 name，返回成功补全的条数。"""
            try:
                name_map = self.fetch_stock_names_full()["names"]
            except Exception as exc:
                logger.warning(
                    "stock_list_cached: 名称补全失败（不写缓存）: %s", exc
                )
                return 0
            filled = 0
            for stock in stocks:
                if not stock.get("name"):
                    name = name_map.get(stock["code"], "")
                    if name:
                        stock["name"] = name
                        filled += 1
            return filled

        def names_are_sparse(stocks: list[dict]) -> bool:
            """名称覆盖率过低说明名称源还没就绪，不能把空名称写盘。"""
            if not stocks:
                return True
            named = sum(1 for stock in stocks if stock.get("name"))
            return named < len(stocks) * 0.8

        def has_unnamed(stocks: list[dict]) -> bool:
            return any(not stock.get("name") for stock in stocks)

        if not refresh:
            loaded = load_stock_codes(path)
            if loaded is not None:
                stocks, saved_date = loaded
                # 自愈：早期冷启动曾把「代码有、名称为空」的表写进当日缓存。
                # 名称组缓存现在可能已就绪，补全后立即覆盖写回。
                if names_are_sparse(stocks):
                    if fill_names(stocks):
                        save_stock_codes(stocks, path)
                    else:
                        logger.warning(
                            "stock_list_cached: 命中缓存但名称稀疏（%s, %d 条），"
                            "名称源仍未就绪",
                            saved_date, len(stocks),
                        )
                elif has_unnamed(stocks) and fill_names(stocks):
                    # 自愈补缺：当日缓存写盘时名称源未就绪（首日并发同步竞态
                    # 落掉部分组）或写盘后才上市的新股（如 920289），名称组
                    # 缓存当日就绪后补全并回写；补不上则保持原样，不空转重写。
                    save_stock_codes(stocks, path)
                else:
                    logger.info("stock_list_cached: 命中缓存 (%s, %d 条)",
                                saved_date, len(stocks))
                return stocks
        # 缓存不存在/过期/强制刷新 → 走网络
        logger.info("stock_list_cached: 缓存未命中，走 stock_list() 拉取...")
        stocks = self.stock_list(timeout=timeout, with_names=with_names)
        # 覆盖 market 字段为派生值（stock_list 返回的 market 恒为 0）
        for s in stocks:
            s["market"] = market_from_code(s["code"])
        # 仅在拿到有效结果时写盘，避免失败的拉取被缓存一整天。
        # 名称稀疏时也绝不写盘：否则空名称会污染当天的前端名称回填。
        if not stocks:
            logger.warning("stock_list_cached: 拉取为空，不写缓存（可重试）")
        elif names_are_sparse(stocks):
            if fill_names(stocks):
                save_stock_codes(stocks, path)
            else:
                logger.warning(
                    "stock_list_cached: 名称覆盖率不足，不写缓存（可重试）"
                )
        else:
            # 覆盖率达标但仍有零星空洞（新股/名称组部分失败）也先补全再写盘，
            # 不把当天的空名称固化（补不上照写，避免整表反复重拉）。
            if has_unnamed(stocks):
                fill_names(stocks)
            save_stock_codes(stocks, path)
        return stocks

    def market_snapshot_with_quotes(
        self,
        timeout: float = 60.0,
        batch_size: int = 30,
    ) -> list[dict]:
        """全市场行情快照：沪深全市场 code+name+准确行情。

        纯双数据源方案（**不依赖 hfd1.0**，彻底避免反复 connect 限流）：

        | 数据源 | 覆盖 | 速度 |
        |--------|------|------|
        | :meth:`stock_list_cached` | 沪深全市场 code+name | ~瞬时(缓存) / ~6s(首次) |
        | :meth:`list_quotes` | 全市场准确行情（批量回填） | ~10-30s |

        旧实现额外调用 hfd1.0 空括号快照拿沪市 code+name，但 hfd1.0 路径
        反复 connect/disconnect 触发 VerifyCode=-1（限流根因，见
        docs/handoffs/HANDOFF.md §7），
        且名称覆盖（1209 锚点）不如 hexin 本地缓存（~8000 条）全，故移除。
        code+name 现完全由 ``stock_list_cached(with_names=True)`` 提供。

        Args:
            timeout: list_quotes 单批超时（秒）。
            batch_size: 每批 list_quotes 数量。

        Returns:
            list[dict]，每项 ``{"code", "name", "price", "change_pct", ...}``。
            code 和 name 来自 stock_list 缓存（hexin 本地名称），数值来自
            list_quotes（盘中准确值，需在交易时段调用）。

        Raises:
            RuntimeError: 未登录。
        """
        self._ensure_main_connection()

        # 1. stock_list 缓存取全量 code+name（含沪深，名称来自 hexin 本地缓存）
        stock_codes = self.stock_list_cached(with_names=True)
        all_by_code: dict[str, dict] = {}
        for s in stock_codes:
            code = s["code"]
            all_by_code[code] = {"code": code, "name": s.get("name", "")}

        # 2. list_quotes 批量回填行情（在主连接上，安全）
        # DataType 字段集（2026-07-23 实测确认含义，见 tests/diag_field_mapping.py）：
        #   dt5=代码 dt6=昨收 dt7=今开 dt8=最高 dt9=最低 dt10=最新价
        #   dt13=成交股数(÷100=手) dt19=成交额(元) dt48=涨速 dt66=涨幅(盘中有效)
        # ⚠ 必须含 dt6（昨收），否则涨跌幅无法本地计算（实测缺 dt6 时返回 None）。
        # ⚠ 字段名必须用 r.get("dt10") 等原始键——list_quotes 返回 dt<N> 原始键，
        #   不是 "price"/"change_pct" 等具名键（旧代码用具名键导致全部 None）。
        datatype = [5, 6, 7, 8, 9, 10, 13, 18, 19, 48, 49]
        codes_all = list(all_by_code.keys())
        quote_count = 0

        for i in range(0, len(codes_all), batch_size):
            batch = codes_all[i:i + batch_size]
            try:
                mkt = market_from_code(batch[0]) if batch else 17
                recs = self.list_quotes(batch, market=mkt,
                                        datatype=datatype,
                                        timeout=min(timeout, 15))
                for r in recs:
                    code = r.get("code", "")
                    if code and code in all_by_code:
                        # 用 list_quotes 实际返回的 dt<N> 原始键回填
                        all_by_code[code].update({
                            "price": r.get("dt10"),
                            "prev_close": r.get("dt6"),
                            "open": r.get("dt7"),
                            "high": r.get("dt8"),
                            "low": r.get("dt9"),
                            "amount": r.get("dt19"),   # 成交额(元)，服务器直接返回
                            "volume": r.get("dt13"),   # 成交股数(÷100=手)
                        })
                        quote_count += 1
            except Exception as e:
                logger.debug("market_snapshot batch %s 失败: %s", batch[:3], e)

        result = list(all_by_code.values())
        logger.info("market_snapshot_with_quotes: %d 条, 回填 %d 条行情",
                    len(result), quote_count)
        return result

    def fetch_stock_names(
        self,
        market: str = "URS",
        stock_name_ver: str = ";;",
        timeout: float = 10.0,
    ) -> dict:
        """通过 upstockname 协议从服务器获取股票名称（探索性能力）。

        **Full names come from** :meth:`fetch_stock_names_full` (network, cross-platform).
        This incremental method is a secondary path for markets not covered by full sync.
        It sends ``method=upstockname`` and parses ``[name_<MARKET>]`` sections.
        The A-share ``name_16_16`` section is decoded by the same 0x0a LZ normalizer;
        see docs/investigations/NAME_16_16_MEMORY_DUMP_PROGRESS.md section 13.
        纯文本段（外汇/期货/北交所/外盘等）直接解出；块状自定义编码段
        （沪深 A 股 ``name_16_16``）当前跳过（编码未逆向，简单模型已穷举证伪，见
        :func:`thspypc.protocol.decode_name_frame` 与
        docs/handoffs/HANDOFF.md §6a/§6b）。

        服务器按账号追踪名称版本，thspypc 账号通常只能拿到**增量**（~12 条），
        全量需 hexin 客户端冷启动触发。本方法适合补充 :meth:`fetch_stock_names_full`
        覆盖不到的市场（外盘/期货）。

        Args:
            market: 市场通道码（``URS``/``UNX``/``UCX``/``UNS``/``UHI`` …）。
            stock_name_ver: 本地版本号，``;;`` 请求全量（实际仍可能只回增量）。
            timeout: 读响应总时长（秒）。

        Returns:
            :func:`decode_name_frame` 的结果 dict::

                {
                  "names": {code: name, ...},
                  "by_segment": {...},
                  "skipped": [...],   # 块状编码、未解的段名
                  "segments": [(seg_name, data_len, kind), ...],
                }

        Raises:
            RuntimeError: 未登录。
        """
        self._ensure_main_connection()
        result = self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._stock_name_service.fetch(
                market=market,
                stock_name_ver=stock_name_ver,
                timeout=timeout,
            ),
        )
        logger.info(
            "fetch_stock_names(market=%s): 解出 %d 条名称，跳过 %d 个块状段",
            market,
            len(result["names"]),
            len(result["skipped"]),
        )
        return result

    def fetch_all_stock_names(
        self,
        timeout: float = 45.0,
        settle_timeout: float = 3.0,
    ) -> dict:
        """Download every market group's names (full stockname replacement).

        Logs into all account-specific 123ths market groups concurrently
        (one socket per group), keeps the sessions alive with 3s heartbeats,
        then replays each group's bootstrap and merges ``[name_*]`` segments
        with per-group txt caches. Cross-platform, no Windows client files.
        Call after login to refresh the full stock-name list.
        """
        material = self._auth_service.require_current()
        account_kind = self.observed_account_profile.kind

        def login_body_factory(group_key: str) -> bytes:
            identity = name_group_login_identity(group_key)
            return self._auth_service.login_body_for_passport(
                material.passport64,
                identity=LoginIdentity(identity),
            )

        result = download_all_stock_names(
            login_body_factory,
            account_kind,
            timeout=timeout,
            settle_timeout=settle_timeout,
        )
        logger.info(
            "fetch_all_stock_names(account=%s): %d names, %d segments",
            account_kind.value,
            len(result["names"]),
            len(result["segments"]),
        )
        return result

    def fetch_stock_names_full(self, timeout: float = 45.0) -> dict:
        """Download the full stock-name list (all market groups), daily-cached.

        Cross-platform, pure TCP: logs into every account-specific 123ths
        market group (shlv2/szlv2 for level2, main for standard), replays each
        group's bootstrap and merges every ``[name_*]`` segment into one map.
        Results are cached per group under ``~/.thspypc/stockname/``; once all
        groups are fresh for the current day, subsequent calls return the
        cached names without any network round-trip.

        Returns:
            ``{"names": {code: name}, "by_segment": {}, "skipped": [], "segments": []}``.
        """
        material = self._auth_service.require_current()
        account_kind = self.observed_account_profile.kind

        def login_body_factory(group_key: str) -> bytes:
            identity = name_group_login_identity(group_key)
            return self._auth_service.login_body_for_passport(
                material.passport64,
                identity=LoginIdentity(identity),
            )

        result = download_all_stock_names(
            login_body_factory,
            account_kind,
            timeout=timeout,
        )
        logger.info(
            "fetch_stock_names_full(account=%s): %d names, %d segments",
            account_kind.value,
            len(result["names"]),
            len(result["segments"]),
        )
        return result

    def list_quotes(
        self,
        codes: list[str],
        market: int = 17,
        datatype: list[int] | None = None,
        pageid: int = 1335,
        timeout: float = 15.0,
    ) -> list[dict]:
        """查个股列表行情（复用登录后的 8901 socket）。

        发送 build_list_quote_query 构造的列表行情请求，解析 hd1.0（≤5 股）
        或 hd3.1（≥6 股）响应，返回记录列表。

        首次调用会按需执行 HTTP 鉴权并建立 MAIN；已有连接时直接复用。
        8901 一条 TCP 响应可能含多个 fdfdfdfd 子帧（CodeListSize / MarketTime
        文本帧 + hd 数据帧）。本方法循环 read_frame，跳过非数据帧，取首个含
        ``hd1.0`` / ``hd3.1`` 标记的帧解析。

        Args:
            codes: 股票代码（纯数字，如 ["600056","600057"]）
            market: 市场码（17=沪 33=深）
            datatype: DataType 字段集（默认=精简7列 LIST_QUOTE_DATATYPE_DEFAULT）
            pageid: 页面 id
            timeout: 单次 read_frame 超时（秒）

        Returns:
            记录列表，每条 dict 含 ``code`` 及若干 ``dt<N>`` 字段，例如::

                {"code": "600056", "dt7": 9.36, "dt10": 9.64, "dt6": 9.5,
                 "dt17": 276800.0, "dt66": 0.0, ...}

            字段语义见 README「DataType 字段含义」表。
            竞价金额 = dt17(竞价量) × dt7(开盘价)，成交额 = dt13(成交量) × dt10(现价)，
            均由调用方本地计算。

        Raises:
            RuntimeError: 未登录（self._sock 为空）
        """
        if datatype is None:
            datatype = LIST_QUOTE_DATATYPE_DEFAULT
        self._ensure_main_connection()
        from ..errors import ProtocolError

        def _query() -> list[dict]:
            try:
                return self._run_default_service(
                    (Capability.BASIC_QUOTE,),
                    lambda: self._quote_service.list_quotes(
                        codes,
                        market=market,
                        datatype=datatype,
                        pageid=pageid,
                        timeout=timeout,
                    ),
                )
            except ProtocolError as exc:
                logger.warning("list_quotes: %s", exc)
                return []
            except OSError as exc:
                # socket 硬死（对端关闭/本地 fd 失效）：与流不同步同样走
                # 下面的重连重试，而不是把 500 抛给 web 层。
                logger.warning("list_quotes: 传输异常 %s", exc)
                return []

        records = _query()
        if records:
            return records
        # 空结果且 MAIN "活着"（探活只验证 TCP 未断，不验证服务端仍在应答）：
        # 收盘后长时间空闲会让流不同步，服务端对该 socket 静默不回。此时
        # connect_main() 走全新 HTTP 鉴权 + 新 Passport 重新登录（>20s 必重连，
        # 不会复用僵死 socket），换新连接后重试一次。每次调用最多重连一次。
        logger.warning(
            "list_quotes: market=%s codes=%s 无数据，重连 MAIN 后重试",
            market, codes[:3],
        )
        if self.connect_main().success:
            return _query()
        return []

    def stock_quote_fields(
        self,
        codes: list[str],
        *,
        timeout: float = 10.0,
        batch_size: int = 40,
    ) -> list[dict]:
        """批量查询统一列表字段（web 左栏 9 列全部可计算列）。

        并发安全：入口经 ``_MAIN_SERIAL_LOCK`` 串行化（多面板同时请求时
        排队执行，不再并发踩 MAIN socket）。
        """
        with _MAIN_SERIAL_LOCK:
            return self._stock_quote_fields_locked(
                codes, timeout=timeout, batch_size=batch_size
            )

    def _stock_quote_fields_locked(
        self,
        codes: list[str],
        *,
        timeout: float = 10.0,
        batch_size: int = 40,
    ) -> list[dict]:
        """批量查询统一列表字段（web 左栏 9 列全部可计算列）。

        每批两路请求（同一连接流水线）：
        1. 基础表 DataType=5,6,7,10,17,19,48 → 涨幅/竞价涨幅/竞价金额/
           成交额/涨速（本地派生，见
           :func:`thspypc.features.quote_protocol.derive_list_quote_fields`）；
        2. 0xc4 金额表（pageid=1334 + ``MONEY_QUOTE_DATATYPE``，2026-08-18
           逆向）→ 主力净额 dt250(元)/DDE 主力 dt248(亿)/总市值 dt202(元)，
           失败仅记 warning 不影响基础列。
        封单额 dt44 不在两表（客户端走 type-02 订阅式按列刷新，未逆向）；
        由 265260 全量排序榜的 60s 缓存补全（``_seal_table``）。

        Args:
            codes: 股票代码列表（市场按前缀自动推断）。
            timeout: 单批 list_quotes 超时（秒）。
            batch_size: 每批代码数。

        Returns:
            list[dict]，每项 ``{code, price, chg_pct, auction_chg_pct,
            auction_amount, amount, speed_4m, main_inflow, dde_main,
            market_cap, seal_amount}``，停牌/缺昨收的派生列为 None。
            单批失败跳过（记 warning），不影响其他批次。
        """
        if not codes:
            return []
        from ..errors import ProtocolError, UnsupportedAccountFeatureError
        from ..features.quote_protocol import (
            MONEY_QUOTE_DATATYPE,
            STOCK_QUOTE_FIELDS_DATATYPE,
            derive_list_quote_fields,
        )

        # 0xc4 金额表单代码请求服务器不应答：凑批时的填充码（结果按
        # 请求 codes 过滤，填充码不会出现在返回里）。
        money_filler = {
            17: "600000", 16: "000001", 33: "000001",
            32: "000001", 151: "920087",
        }

        self._ensure_main_connection()
        groups: dict[int, list[str]] = {}
        for code in codes:
            groups.setdefault(self._market_for_code(code), []).append(code)

        rows: dict[str, dict] = {}
        for market, market_codes in groups.items():
            for i in range(0, len(market_codes), batch_size):
                chunk = market_codes[i : i + batch_size]
                try:
                    records = self.list_quotes(
                        chunk,
                        market=market,
                        datatype=STOCK_QUOTE_FIELDS_DATATYPE,
                        timeout=timeout,
                    )
                except ProtocolError as exc:
                    logger.warning(
                        "stock_quote_fields: market=%s 批次 %s 失败: %s",
                        market, chunk[:3], exc,
                    )
                    continue
                for record in records:
                    code = str(record.get("code", ""))
                    if code:
                        rows[code] = derive_list_quote_fields(record)
                # 0xc4 金额表补主力净额/DDE/总市值（北交所等未验证市场失败即跳过）
                money_chunk = chunk
                if len(money_chunk) == 1:
                    filler = money_filler.get(market)
                    if filler and filler != money_chunk[0]:
                        money_chunk = [money_chunk[0], filler]
                try:
                    money_records = self.list_quotes(
                        money_chunk,
                        market=market,
                        datatype=MONEY_QUOTE_DATATYPE,
                        pageid=1334,
                        timeout=timeout,
                    )
                except (
                    ProtocolError,
                    UnsupportedAccountFeatureError,
                    OSError,
                ) as exc:
                    logger.warning(
                        "stock_quote_fields: market=%s 金额表 %s 失败: %s",
                        market, money_chunk[:3], exc,
                    )
                    money_records = []
                for record in money_records:
                    code = str(record.get("code", ""))
                    if not code or code not in rows:
                        continue
                    money = derive_list_quote_fields(record)
                    for key in ("main_inflow", "dde_main", "market_cap"):
                        if money.get(key) is not None:
                            rows[code][key] = money[key]
                    if rows[code].get("amount") is None and money.get("amount") is not None:
                        rows[code]["amount"] = money["amount"]

        # 封单额：0xc4 金额表无 dt44，客户端走 type-02 订阅式按列刷新
        # （未逆向）；用已验证的 265260 全量排序榜做 TTL 缓存补全
        # （L2 SortCount 放大 ~0.1s，仅约 2899 只涨停/停牌参与股有值）。
        seal_map = self._seal_table()
        if seal_map:
            for code in rows:
                seal = seal_map.get(code)
                if seal is not None:
                    rows[code]["seal_amount"] = seal
        return [rows[code] for code in codes if code in rows]

    _SEAL_TTL = 60.0

    def _seal_table(self) -> dict[str, float]:
        """code→dt44(封单额,元) 全市场表，60s 缓存；失败返回上次结果或空。"""
        import time

        now = time.monotonic()
        cache = self.__dict__.get("_seal_cache")
        if cache and now - cache[0] < self._SEAL_TTL:
            return cache[1]
        try:
            ranked = self.stock_list_hot(
                count=5400,
                sort_by=265260,
                sort_dir="D",
                with_values=True,
            )
        except (ProtocolError, OSError, RuntimeError) as exc:
            logger.warning("stock_quote_fields: 封单额表拉取失败: %s", exc)
            # 失败也写入短期负缓存。否则每个可视窗口 quotes_ext 都会立刻
            # 重跑一次 5400 股排序；服务端字段漂移期间会放大成连续 L2 请求，
            # 甚至触发连接层重新鉴权。已有旧真值时继续沿用旧表。
            table = cache[1] if cache else {}
            self.__dict__["_seal_cache"] = (now, table)
            return table
        table = {
            str(r.get("code")): r["dt44"]
            for r in ranked
            if r.get("dt44")
        }
        self.__dict__["_seal_cache"] = (now, table)
        logger.info("封单额表已刷新: %d 只", len(table))
        return table

    def depth_quote(
        self,
        code: str,
        market: int = 0,
        timeout: float = 12.0,
        retries: int = 2,
        ten_levels: bool = False,
    ) -> DepthQuote:
        """查询个股买卖盘（默认五档；``ten_levels=True`` 请求 Level2 十档）及涨跌停封单额。

        五档为普通账号完整复刻口径；十档仅 Level2 账号有，且必须走对应市场
        L2 连接（沪 shlv2 / 深 szlv2，pageid=4214），不能走 MAIN——MAIN 上
        即使带完整 DataType 也只回 0xFFFFFFFF 哨兵。盘后服务器仍会返回最后
        一份盘口快照（含十档真实挂单）。返回值包含 ``buy``、``sell``、
        ``seal_amount``、``seal_type`` 和原始 ``fields``；无盘口数据时返回
        空字典。

        Args:
            code: 六位股票代码。
            market: 0=按代码推断，17=沪市，33=深市。
            timeout: 单次响应读取超时（秒）。
            retries: 连接异常后的重试次数。
            ten_levels: True=请求十档（Level2 账号），False=五档。
        """
        if market == 0:
            market = self._market_for_code(code)
        # 北交所（151）盘口走 10443 的 76/77/78/79 五档字段，尚未实现；
        # 沪深式 L2 十档通道不存在，直接返回空盘口（文档约定），不抛错。
        if market == 151:
            return {}
        last_err = ""
        for attempt in range(retries + 1):
            if not self.is_connected:
                logger.info("depth_quote: 连接不可用，connect（attempt %d/%d）",
                            attempt + 1, retries)
                lr = self.connect()
                if not lr.success:
                    last_err = f"connect 失败: {lr.error}"
                    continue
            try:
                from ..errors import ProtocolError

                try:
                    capability = (
                        (Capability.L2_SNAPSHOT_PUSH,)
                        if ten_levels
                        else (Capability.BASIC_QUOTE,)
                    )
                    return self._run_default_service(
                        capability,
                        lambda: self._quote_service.depth_quote(
                            code,
                            market=market,
                            timeout=timeout,
                            ten_levels=ten_levels,
                        ),
                    )
                except ProtocolError as exc:
                    logger.warning("depth_quote: %s", exc)
                    return {}
            except (ConnectionError, OSError, TimeoutError) as e:
                last_err = f"{type(e).__name__}: {e}"
                logger.warning("depth_quote %s 失败（attempt %d）: %s",
                               code, attempt + 1, last_err)
                self._drop_connection()
        raise RuntimeError(f"depth_quote {code} 重试 {retries} 次仍失败: {last_err}")

    def market_view_pipeline(
        self,
        code: str,
        market: int = 0,
        timeout: float = 12.0,
    ) -> tuple[dict | None, DepthQuote]:
        """Return quote and five-level depth using one bounded MAIN pipeline.

        与 stock_quote_fields 共用 ``_MAIN_SERIAL_LOCK`` 串行化，避免多面板
        quotes_ext 与切股盘口并发踩同一条 MAIN socket。
        """
        if market == 0:
            market = self._market_for_code(code)
        self._ensure_main_connection()
        with _MAIN_SERIAL_LOCK:
            try:
                return self._run_default_service(
                    (Capability.BASIC_QUOTE,),
                    lambda: self._quote_service.market_view_pipeline(
                        code,
                        market=market,
                        timeout=timeout,
                    ),
                )
            except ProtocolError as exc:
                logger.warning("market_view_pipeline: %s", exc)
                return None, {}

    def kline(
        self,
        code: str,
        period: str = "day",
        count: int = 2146,
        anchor: int = 0,
        fuquan: str = "Q",
        market: int = 0,
        timeout: float = 12.0,
        retries: int = 3,
        channel: str = "auto",
        latest: bool = False,
    ) -> list[dict]:
        """查 K线（复用登录后的 8901 长连接，复刻 hexin 单连接连发模式）。

        发送 ``build_kline_query`` 构造的 K线请求，解析 hd1.0/hd3.1
        变体响应（flag=0x0042/0x0046），返回 OHLCV 记录列表。新股首日等
        短历史由服务端返回 hd1.0，批量历史返回 hd3.1。

        **连接复用**（关键）：抓包确认 hexin 在**同一条 TCP 长连接**上连发日/周/
        月/5分K 请求（不轮换 IP）。本方法复用 ``self._sock``，首次调用触发 connect()，
        后续调用复用同一条连接——这避免了每次重连新建短连接时的会话不稳定
        （周/月K route=0x014e 在新连接上易被 RST，长连接复用则稳定）。

        **重试**：连接断开或读超时时自动 ensure_connected + 重试（最多 ``retries`` 次）。
        每次重试用 IP 轮换取新连接（测速缓存 + 轮换偏移），命中稳定 IP 即成功。

        Args:
            code: 股票代码（纯数字，如 "000089"）
            period: 周期名（"1min"/"5min"/"15min"/"30min"/"60min"/"day"/
                "week"/"month"/"quarter"/"year"）
            count: 取的根数（窗口含端点，服务端返回 count+1 根，受上市日截断）
            anchor: 窗口终点（默认 0=最新一根；日/周/月/季/年K 传 YYYYMMDD，
                分钟K 传 bar_index；翻页=把上一窗口最早一根的日期/bar_index 传进来）
            fuquan: 复权（"Q"=前复权 "H"=后复权 ""=不复权）
            market: 市场码（0=按代码前缀自动推断：6xx=沪17，其余=深33）
            timeout: 单次 read_frame 超时（秒）
            retries: 连接失败时的重试次数（每次重连轮换 IP）

        Returns:
            记录列表，每条 ``{code, time, open, high, low, close, volume,
            amount, bar_index?, dt<N>...}``，按时间正序。日内K（5分等）的
            ``time`` 为 None、原 dt1 值存 ``bar_index``。

        Raises:
            ValueError: period 不在支持列表内。
            RuntimeError: 重试 ``retries`` 次后仍失败。
        """
        if period not in self._KLINE_PERIOD_CODES:
            raise ValueError(f"period 不支持: {period}，可选: {list(self._KLINE_PERIOD_CODES)}")
        period_code = self._KLINE_PERIOD_CODES[period]
        if market == 0:
            market = self._market_for_code(code)

        # 按账号类型选 capability：普通=BASIC_QUOTE(MAIN)，Level2=L2_TIMELINE(L2连接)
        # 2026-08-05 抓包对齐：Level2 K线走 pageid=1334 + L2 连接（见 build_kline_l2_query）
        profile = (
            self._service_connections.profile
            if self._service_connections is not None
            else self.observed_account_profile
        )
        if channel not in ("auto", "level2", "ifindhq_fast"):
            raise ValueError(
                "channel must be auto, level2, or ifindhq_fast"
            )
        use_l2 = (
            profile.kind is AccountKind.LEVEL2
            if channel == "auto"
            else channel == "level2"
        )
        kline_capability = (
            Capability.L2_TIMELINE if use_l2 else Capability.BASIC_QUOTE
        )

        last_err = ""
        for attempt in range(retries + 1):
            # ensure_connected 对从未登录会 raise；这里统一用 is_connected 判断，
            # 连接不在则 connect()（首次登录 + 断线重连都走这里，IP 轮换取新连接）
            # KLINE_FAST has its own managed connection.  Probing MAIN here
            # couples an independent K-line retry to a possibly busy quote
            # socket and can freeze /api/status plus the final stock request.
            if channel != "ifindhq_fast" and not self.is_connected:
                logger.info("kline: 连接不可用，connect（attempt %d/%d，IP 轮换）",
                            attempt + 1, retries)
                lr = self.connect()
                if not lr.success:
                    last_err = f"connect 失败: {lr.error}"
                    continue
            try:
                from ..errors import ProtocolError

                try:
                    recs = self._run_default_service(
                        (kline_capability,),
                        lambda: self._kline_service.kline(
                            code,
                            market=market,
                            period=period_code,
                            count=count,
                            anchor=anchor,
                            fuquan=fuquan,
                            timeout=timeout,
                            channel=channel,
                            latest=latest,
                        ),
                    )
                except ProtocolError as exc:
                    logger.warning("kline: %s", exc)
                    recs = []
                # 不再做"坏 IP/数据完整性"校验：登录成功即信任该 IP，服务端返回
                # 多少根就是多少（新股/上市日截断/坏 IP 都无需区分）。
                return recs
            except (ConnectionError, OSError, TimeoutError) as e:
                last_err = f"{type(e).__name__}: {e}"
                logger.warning("kline %s %s 失败（attempt %d, IP=%s）: %s",
                               code, period, attempt + 1, self._connected_ip or "?", last_err)
                # 传输失败仅断连重试，不拉黑 IP（登录成功即好 IP）
                if channel == "ifindhq_fast":
                    if self._service_connections is not None:
                        self._service_connections.close(
                            ConnectionRole.KLINE_FAST
                        )
                else:
                    self._drop_connection()
        raise RuntimeError(f"kline {code} {period} 重试 {retries} 次仍失败: {last_err}")

    def _index_previous_close(
        self,
        code: str,
        *,
        market: int,
        target_date: date_type,
        timeout: float,
    ) -> float | None:
        """Fetch the last daily close strictly before ``target_date``."""
        anchor = int(target_date.strftime("%Y%m%d"))
        bars = self.kline(
            code,
            period="day",
            count=10,
            anchor=anchor,
            fuquan="",
            market=market,
            timeout=timeout,
            retries=1,
        )
        candidates: list[tuple[date_type, float]] = []
        for bar in bars:
            bar_time = bar.get("time")
            close = bar.get("close")
            if close is None or not isinstance(bar_time, datetime):
                continue
            bar_date = bar_time.date()
            if bar_date < target_date:
                candidates.append((bar_date, float(close)))
        if not candidates:
            return None
        return max(candidates, key=lambda item: item[0])[1]

    def _enrich_index_timeline(
        self,
        records: list[dict],
        code: str,
        *,
        market: int,
        target_date: date_type,
        prev_close: float | None,
        timeout: float,
    ) -> list[dict]:
        from ..features.timeline_protocol import enrich_index_lead_line

        if prev_close is None:
            try:
                prev_close = self._index_previous_close(
                    code,
                    market=market,
                    target_date=target_date,
                    timeout=timeout,
                )
            except Exception as exc:
                logger.warning(
                    "指数领先线昨收查询失败 %s %s: %s",
                    code,
                    target_date,
                    exc,
                )
        return enrich_index_lead_line(records, prev_close)

    def timeline(
        self,
        code: str,
        market: int = 0,
        timeout: float = 12.0,
        prev_close: float | None = None,
    ) -> list[dict]:
        """查当日分时图（含指数白线及领先线）。

        普通账号走 MAIN 上的 ``pageid=9355`` 请求-响应；Level2 账号走
        ``pageid=4214`` 的市场专用通道。两种响应统一返回逐点行情记录。

        Args:
            code: 股票或指数代码（如 ``"000938"``、``"1A0001"``）。
            market: 市场码（0=按代码前缀自动推断，含 1A/1B/399 指数）。
            timeout: 单次 read_frame 超时（秒）。
            prev_close: 指数昨收；不传时自动查询前一交易日日 K 收盘。

        Returns:
            记录列表，每条 ``{time, dt10(现价), dt13(量), dt19(额), ...}``，
            按时间正序。指数记录额外包含 ``dt40``、``lead_change_bp``、
            ``lead_change_pct``、``prev_close``、``lead_price``；其中
            ``lead_price`` 即领先线（黄线）绝对点位。

        Raises:
            RuntimeError: 未登录或 L2 市场连接建立失败。
        """
        if market == 0:
            market = self._market_for_code(code)
        market = _intraday_market(market)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        profile = (
            self._service_connections.profile
            if self._service_connections is not None
            else self.observed_account_profile
        )
        capability = (
            Capability.BASIC_TIMELINE
            if profile.kind is AccountKind.STANDARD
            else Capability.L2_TIMELINE
        )
        # The push reader and request/response services share the market's
        # ManagedConnection request lock.  An active WebSocket subscription is
        # therefore not a competing socket reader: the request temporarily
        # owns the lane and the push reader resumes afterwards.
        records = self._run_default_service(
            (capability,),
            lambda: self._timeline_service.timeline(
                code,
                market=market,
                timeout=timeout,
            ),
        )
        if market in (16, 32, 144) and records:
            return self._enrich_index_timeline(
                records,
                code,
                market=market,
                target_date=date_type.today(),
                prev_close=prev_close,
                timeout=timeout,
            )
        return records

    def auction(
        self,
        code: str,
        market: int = 0,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        """查集合竞价（9:15-9:25 的撮合价、领先价、累计量及未匹配量）。

        普通账号走 MAIN：当天请求用 ``pageid=9354/period=7176``，历史交易日
        用 ``pageid=9355/period=6144``。Level2 账号：竞价时段(9:15-9:25)走
        ``pageid=1334/period=7176`` 实时路径拿实时撮合；**非竞价时段走 L2
        历史路径 pageid=4417** 拿当日完整竞价序列(~39ms)，避免实时路径在非竞价
        时段死等 timeout(盘后偶发 12s+)。沪深指数改走 ``pageid=6240`` 的
        ``T_URL`` 请求-响应；同花顺 PC 界面在竞价时段约每 10 秒轮询一次，本方法
        执行其中一次查询并返回当时已生成的全部 ``Auction`` 记录，不启动后台轮询。

        Args:
            code: 股票或指数代码（如 ``"000938"``、``"1A0001"``）。
            market: 市场码（0=按代码前缀自动推断，含 1A/1B=沪指16、399=深指32）。
            trade_date: 交易日。``None``（默认）= 最近交易日；传 ``date``/``datetime``
                = 指定交易日（算该日 9:15/9:25 unix 时间戳）。沪深竞价时段相同。
                ★ 历史日期的 DateTime 格式基于当日抓包推断，若实测不符需调整。
                指数 T_URL 只提供当前交易日，因此指数只能传 ``None`` 或今天。
            timeout: 单次 read_frame 超时（秒）。

        Returns:
            集合竞价记录列表。指数 T_URL 响应返回 ``dt10``（白线）及
            ``lead_price``/``leadprice``（黄线）；个股记录为 ``{time,
            dt10(撮合价), dt49(累计量·股),
            dt27(买方未匹配·股), dt33(卖方未匹配·股)}``，按时间正序
            （9:15:00-9:24:57）。非交易日/无竞价数据时返回空列表。

            ``dt27`` / ``dt33`` 的「无值」哨兵归一化为 ``None``（如该方向无未匹配
            委托），与真实 ``0.0`` 区分。每条 tick 因撮合被动方被吃光，dt27/dt33
            恰好一侧为 None。

            ⚠ ``dt33`` 在竞价接口=卖方未匹配量，但在分时接口=成交额、在 list_quotes=
            注册制上市日。dt 号是协议槽位号，语义由字段表定义，勿跨接口混淆。

        Raises:
            RuntimeError: 未登录或 L2 市场连接建立失败。
        """
        if market == 0:
            market = self._market_for_code(code)
        market = _intraday_market(market)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        profile = (
            self._service_connections.profile
            if self._service_connections is not None
            else self.observed_account_profile
        )
        capability = (
            Capability.BASIC_AUCTION
            if profile.kind is AccountKind.STANDARD
            else Capability.L2_AUCTION
        )
        return self._run_default_service(
            (capability,),
            lambda: self._auction_service.auction(
                code,
                market=market,
                trade_date=trade_date,
                timeout=timeout,
            ),
        )

    def superorder(
        self,
        code: str,
        start,
        end,
        *,
        market: int = 0,
        pageid: int = 4214,
        timeout: float = 12.0,
    ) -> list[dict]:
        """查逐笔成交回放（period=7169，超级盘口 / 逐笔面板按区间拖动所见）。

        返回 ``[start, end]`` 区间内每一笔撮合的逐笔记录。**仅 Level2 账号可用**
        （普通账号无 L2 通道）。走对应市场的 Level2 连接（沪 shlv2 / 深 szlv2），
        先 4214 注册再发 7169 区间请求。

        Args:
            code: 股票代码（如 ``"000938"``、``"603118"``）。
            start: 区间起点，``datetime`` / ``time`` / unix 秒 int 均可。
                ``time`` 对象按当日日期补全；int 视为 unix 时间戳。
            end: 区间终点，类型规则同 ``start``。
            market: 市场码（0=按代码前缀自动推断）。
            pageid: ``4214``（逐笔面板，默认）或 ``4260``（超级盘口）。两通道响应同构。
            timeout: 单次 read_frame 超时（秒）。

        Returns:
            逐笔记录列表，每条 ``{code, time, price, volume, direction,
            delegate_a, delegate_b, seq, trade_no, dt1, dt56, ...}``，按时间正序。

        Raises:
            CapabilityUnavailableError: 普通账号无 L2 通道。
        Note:
            ``delegate_a``(dt12)/``delegate_b``(dt74) 的买卖语义沪深不同：深市
            a=卖方/b=买方，沪市 a=主动方/b=被动方挂单。详见
            ``superorder_protocol`` 模块 docstring。
        """
        if market == 0:
            market = self._market_for_code(code)
        start_ts = self._superorder_ts(start)
        end_ts = self._superorder_ts(end)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        # 北交所无沪深式 7169 回放通道：官方客户端走 pageid=10443 的
        # DateTime=7176 平文本窗口（MAIN 连接，2026-09-08 双账号抓包确认），
        # 返回秒级逐笔（时间不连续，BSE 流动性差）。
        if market == 151:
            from ..services.superorder import bse_tick_window

            return self._run_default_service(
                (),
                lambda: bse_tick_window(
                    self._superorder_service,
                    code,
                    market=market,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    timeout=timeout,
                ),
            )
        # request() 与后台推送读取线程共享每市场 request lock；请求期间若先收到
        # 主动推送，SuperorderService 会交回统一事件分发器，不会丢帧或双 recv。
        return self._run_default_service(
            (Capability.L2_TIMELINE,),
            lambda: self._superorder_service.superorder(
                code,
                market=market,
                start_ts=start_ts,
                end_ts=end_ts,
                pageid=pageid,
                timeout=timeout,
            ),
        )

    def bse_superorder_day(
        self,
        code: str,
        *,
        market: int = 0,
        timeout: float = 20.0,
    ) -> list[dict]:
        """北交所当日盘中超级盘口：1207 页 4096 全日窗（逐笔+五档快照）。

        2026-09-08 复抓确认官方"超级盘口"页当日形态；仅当日可用（历史
        日期官方无超级盘口页）。每行含 ts/价/单笔量/累计量额与五档价量。
        """
        if market == 0:
            market = self._market_for_code(code)
        from ..services.superorder import bse_superorder_day as bse_superorder_day_svc

        return self._run_default_service(
            (),
            lambda: bse_superorder_day_svc(
                self._superorder_service,
                code,
                market=market,
                timeout=timeout,
            ),
        )

    @staticmethod
    def _superorder_ts(value) -> int:
        """把 datetime / time / int 统一转成 unix 时间戳（秒）。"""
        if isinstance(value, int):
            return value
        if isinstance(value, datetime):
            return int(value.timestamp())
        # time 对象：按当日补全
        from datetime import date as _date
        combined = datetime.combine(_date.today(), value)
        return int(combined.timestamp())

    def snapshot_replay(
        self,
        code: str,
        *,
        market: int = 0,
        start=None,
        end=None,
        timeout: float = 30.0,
    ) -> list[dict]:
        """查盘口快照回放（period=4096，超级盘口分时曲线）。

        返回区间内每 ~3 秒一个完整盘口快照，每条含十档买卖价量。
        **仅 Level2 账号可用**。
        - 不传 ``start/end``：盘中路径 pageid=4260，``4096(0-0)`` 当日全天。
        - 传 ``start/end``（datetime / time / unix 秒）：盘后/历史路径
          pageid=4417，``4096(<start>-<end>)``（2026-08-07 抓包对齐）。

        Args:
            code: 股票代码（如 ``"000938"``、``"603118"``）。
            market: 市场码（0=按代码前缀自动推断）。
            start: 区间起点，``datetime`` / ``time`` / unix 秒 int 均可。
            end: 区间终点，类型规则同 ``start``。
            timeout: 单次 read_frame 超时（秒）。全天数据 ~500KB，默认 30s。

        Returns:
            盘口快照记录列表，每条 ``{time, ts, price, dt24-35(五档),
            dt102-125(六~十档), ...}``，按时间正序。

        Raises:
            CapabilityUnavailableError: 普通账号无 L2 通道。
        """
        if market == 0:
            market = self._market_for_code(code)
        historical = start is not None or end is not None
        start_ts = self._superorder_ts(start) if start is not None else 0
        end_ts = self._superorder_ts(end) if end is not None else 0
        if market in (16, 32, 144):
            # 指数超级盘口统一走 pageid=77（2026-08-07 抓包，盘中盘后都是）；
            # 0-0 与历史区间作为同一帧的两个查询对发出。
            pageid = SNAPSHOT_REPLAY_INDEX_PAGEID
        elif historical:
            # 个股盘后/历史走 4417。
            pageid = SNAPSHOT_REPLAY_HIST_PAGEID
        else:
            pageid = SNAPSHOT_REPLAY_PAGEID
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        return self._run_default_service(
            (Capability.L2_TIMELINE,),
            lambda: self._superorder_service.snapshot_replay(
                code,
                market=market,
                start_ts=start_ts,
                end_ts=end_ts,
                pageid=pageid,
                timeout=timeout,
            ),
        )

    def order_details(
        self,
        code: str,
        start=-29,
        end=0,
        *,
        market: int = 0,
        timeout: float = 30.0,
    ) -> dict:
        """查 4214 看盘页的全量挂单、买撤和卖撤明细。

        ``start/end`` 接受 ``datetime``、``time`` 或 Unix 秒；默认 ``-29-0``
        返回各路最新一页。传绝对时间区间可一次取回该区间的全部记录。撤单行
        同时返回挂单/撤单时间及 ``elapsed_seconds``，并尽可能通过委托号回连
        ``orders`` 中的原挂单。
        """
        if market == 0:
            market = self._market_for_code(code)
        start_ts = self._superorder_ts(start)
        end_ts = self._superorder_ts(end)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        return self._run_default_service(
            (Capability.L2_TIMELINE,),
            lambda: self._superorder_service.order_details(
                code,
                market=market,
                start_ts=start_ts,
                end_ts=end_ts,
                timeout=timeout,
            ),
        )

    @staticmethod
    def _order_queue_context(trade_date) -> tuple[int, int]:
        """把历史交易日转换成 4417@4096 的全天上下文区间。"""
        if trade_date is None:
            return 0, 0
        value = trade_date
        if isinstance(value, str):
            value = date_type.fromisoformat(value)
        if isinstance(value, datetime):
            value = value.date()
        if not isinstance(value, date_type):
            raise TypeError("trade_date 必须是 date/datetime/'YYYY-MM-DD'/None")
        start = datetime.combine(value, datetime.min.time()).replace(
            hour=9,
            minute=10,
        )
        end = datetime.combine(value, datetime.min.time()).replace(
            hour=15,
            minute=1,
        )
        return int(start.timestamp()), int(end.timestamp())

    def order_queue(
        self,
        code: str,
        side: str = "buy",
        *,
        market: int = 0,
        trade_date=None,
        timeout: float = 12.0,
    ) -> dict:
        """查买一或卖一委托队列（7173/7174，Level2 专属）。

        ``side='buy'`` 查 7173 买一队列，``side='sell'`` 查 7174 卖一队列。
        传 ``trade_date`` 时先在同一市场 L2 连接用 4096 建立 4417 历史上下文。
        当前仅确认最近一个交易日有队列数据，更早日期可能返回空队列。
        """
        if market == 0:
            market = self._market_for_code(code)
        context_start, context_end = self._order_queue_context(trade_date)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        return self._run_default_service(
            (Capability.L2_TIMELINE,),
            lambda: self._superorder_service.order_queue(
                code,
                side=side,
                market=market,
                context_start_ts=context_start,
                context_end_ts=context_end,
                timeout=timeout,
            ),
        )

    def order_queues(
        self,
        code: str,
        *,
        market: int = 0,
        trade_date=None,
        timeout: float = 12.0,
    ) -> dict[str, dict]:
        """查买一和卖一队列；历史调用只建立一次 4096/4417 上下文。"""
        if market == 0:
            market = self._market_for_code(code)
        # 北交所无 7173/7174 队列通道：返回空队列（前端显示空），不抛错。
        if market == 151:
            return {}
        context_start, context_end = self._order_queue_context(trade_date)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        return self._run_default_service(
            (Capability.L2_TIMELINE,),
            lambda: self._superorder_service.order_queues(
                code,
                market=market,
                context_start_ts=context_start,
                context_end_ts=context_end,
                timeout=timeout,
            ),
        )

    def closing_auction(
        self,
        code: str,
        market: int = 0,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        """查 14:57-15:00 尾盘集合竞价逐点行情。

        普通账号走 MAIN：当天 ``pageid=9354``，历史日 ``pageid=9355``。
        Level2 账号走对应市场连接：当天 ``pageid=4214``，历史日
        ``pageid=4417``。两类账号都使用 ``period=7424``，但连接、页号和
        请求头不混用。
        """
        if market == 0:
            market = self._market_for_code(code)
        market = _intraday_market(market)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        profile = (
            self._service_connections.profile
            if self._service_connections is not None
            else self.observed_account_profile
        )
        capability = (
            Capability.BASIC_AUCTION
            if profile.kind is AccountKind.STANDARD
            else Capability.L2_AUCTION
        )
        return self._run_default_service(
            (capability,),
            lambda: self._auction_service.closing_auction(
                code,
                market=market,
                trade_date=trade_date,
                timeout=timeout,
            ),
        )

    def intraday(
        self,
        code: str,
        market: int = 0,
        trade_date=None,
        timeout: float = 12.0,
        retries: int = 3,
    ) -> list[dict]:
        """返回同花顺式完整日内序列：早盘竞价、盘中、尾盘竞价。

        每条记录增加 ``phase``，值依次为 ``opening_auction``、
        ``continuous``、``closing_auction``。历史交易日自动选择账号对应的
        历史分时与竞价协议；普通账号使用 9354/9355，Level2 使用 4214/4417。
        """
        if market == 0:
            market = self._market_for_code(code)
        market = _intraday_market(market)
        value = trade_date
        if isinstance(value, str):
            value = date_type.fromisoformat(value)
        elif isinstance(value, datetime):
            value = value.date()
        elif value is None:
            value = latest_trade_date()
        service_trade_date = value if trade_date is None else trade_date
        historical = value is not None and value != date_type.today()

        historical_index = historical and market in (16, 32, 144)
        # 北交所（151）：早盘竞价（09:15-09:25）用 6144 历史竞价窗（当日/
        # 历史同一协议，2026-09-08 抓包对齐）；分时主体当日走 1 分钟K合成，
        # 历史日期走 pageid=10444 的 8192 packed-date bar 窗；无尾盘竞价。
        bse_stock = market == 151
        profile = (
            self._service_connections.profile
            if self._service_connections is not None
            else self.observed_account_profile
        )
        if (
            profile.kind is AccountKind.LEVEL2
            and market not in (16, 32, 144, 151)
        ):
            last_err: Exception | None = None
            for attempt in range(2):
                try:
                    return self._run_default_service(
                        (
                            Capability.L2_AUCTION,
                            Capability.L2_HISTORY_TIMELINE,
                        ),
                        lambda: self._auction_service.intraday(
                            code,
                            market=market,
                            trade_date=service_trade_date,
                            timeout=timeout,
                        ),
                    )
                except (ProtocolError, ChannelUnavailableError) as exc:
                    # 首次切换股票时 4214 注册/4417 伴随帧偶发 CodeListSize=0
                    # 或首帧解析失败；同连接重试一次通常即成功。
                    last_err = exc
                    logger.warning(
                        "intraday %s market=%s L2 bundle 失败（attempt %d）: %s",
                        code, market, attempt + 1, exc,
                    )
                    if attempt == 0:
                        time.sleep(0.15)
                        continue
            # 重试仍失败时降级为纯盘中分时，保证图表不空白，而不是直接 502。
            try:
                fallback = self.timeline(
                    code,
                    market=market,
                    timeout=timeout,
                )
            except Exception:
                raise last_err
            return [
                {"phase": "continuous", **record}
                for record in fallback
            ]

        opening = (
            self._bse_opening_auction(
                code,
                market=market,
                trade_date=value,
                timeout=min(timeout, 8.0),
            )
            if bse_stock
            else []
            if historical_index
            else self.auction(
                code,
                market=market,
                trade_date=value,
                timeout=timeout,
            )
        )
        if historical:
            # 北交所历史分时：pageid=10444 的 8192 packed-date 窗
            # （2026-09-08 日期标定抓包，bar=packed(日期)×2048+606）。
            continuous = (
                self._bse_history_timeline(
                    code,
                    market=market,
                    trade_date=value,
                    timeout=timeout,
                    retries=retries,
                )
                if bse_stock
                else self.history_timeline(
                    code,
                    value,
                    market=market,
                    timeout=timeout,
                    retries=retries,
                )
            )
        else:
            continuous = (
                self._bse_timeline_from_kline(
                    code,
                    market=market,
                    timeout=timeout,
                )
                if bse_stock
                else self.timeline(
                    code,
                    market=market,
                    timeout=timeout,
                )
            )
        closing = (
            []
            if historical_index or bse_stock
            else self.closing_auction(
                code,
                market=market,
                trade_date=value,
                timeout=timeout,
            )
        )

        result: list[dict] = []
        for phase, records in (
            ("opening_auction", opening),
            ("continuous", continuous),
            ("closing_auction", closing),
        ):
            result.extend(
                {"phase": phase, **record}
                for record in records
            )
        return result

    def _bse_timeline_from_kline(
        self,
        code: str,
        *,
        market: int,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        """北交所分时：用 1 分钟 K 线合成与沪深 timeline 同构的记录。

        2026-09-08 抓包确认官方客户端对 BSE 分时的驱动请求是 route=0x014f
        的 1 分钟K（pageid=1334，DataType=7,13,19,11,74,9,8,...），而
        pageid=10443 分时协议请求只回 ACK 不回数据。合成的 dt13/dt19 为
        累计量/额（与沪深分时字段语义一致）；无 dt14/15 与 dt227/229
        （北交所无买卖力量/大单字段，与官方客户端一致）。

        仅支持当日（最新一窗按 bar_index 间隔切段，午休 ~90、隔夜远大于
        此，取最后一段）。历史日期走 :meth:`_bse_history_timeline`
        （pageid=10444 的 8192 packed-date bar 窗，2026-09-08 已逆向）；
        本方法历史日期返回空表。
        """
        if trade_date is not None and str(trade_date) != str(
            date_type.today()
        ):
            return []
        bars = self.kline(
            code,
            period="1min",
            count=300,
            fuquan="N",
            market=market,
            timeout=timeout,
            retries=0,
        )
        if not bars:
            return []
        # 切段：取最后一个 bar_index 连续段（午休间隔≈90，隔夜≫120）
        start = 0
        for i in range(1, len(bars)):
            prev_idx = bars[i - 1].get("bar_index") or 0
            cur_idx = bars[i].get("bar_index") or 0
            if cur_idx - prev_idx > 120:
                start = i
        session = bars[start:]
        rows: list[dict] = []
        cum_volume = 0.0
        cum_amount = 0.0
        for i, bar in enumerate(session):
            volume = float(bar.get("volume") or 0)
            amount = float(bar.get("amount") or 0)
            cum_volume += volume
            cum_amount += amount
            close = bar.get("close")
            rows.append(
                {
                    "code": code,
                    "minute_index": i,
                    "bar_index": bar.get("bar_index"),
                    "dt7": bar.get("open"),
                    "dt8": bar.get("high"),
                    "dt9": bar.get("low"),
                    "dt10": close,
                    "dt11": close,
                    "dt13": cum_volume,
                    "dt19": cum_amount,
                }
            )
        return rows

    def _bse_history_timeline(
        self,
        code: str,
        *,
        market: int,
        trade_date,
        timeout: float = 12.0,
        retries: int = 1,
    ) -> list[dict]:
        """北交所历史分时：pageid=10444 嵌套 8192 packed-date bar 窗。

        2026-09-08 日期标定抓包确认 bar 窗 = ``packed(日期)×2048+606`` 起、
        宽 355（与沪深 packed-date 游标同一公式）；响应个股表为
        0x0042/rs28/fc7，241 行/日。失败或非交易日返回空表（不造数据）。
        """
        from ..services.timeline import bse_history_timeline

        last_err: Exception | None = None
        for attempt in range(max(retries, 1)):
            try:
                rows = self._run_default_service(
                    (),
                    lambda: bse_history_timeline(
                        self._timeline_service,
                        code,
                        date=trade_date,
                        market=market,
                        timeout=timeout,
                    ),
                )
            except (ConnectionError, OSError, TimeoutError) as exc:
                last_err = exc
                logger.warning(
                    "BSE 历史分时 %s %s 失败（attempt %d）: %s",
                    code, trade_date, attempt + 1, exc,
                )
                if self._service_connections is not None:
                    self._service_connections.close(ConnectionRole.BSE_MAIN)
                continue
            if rows:
                return [
                    {
                        "code": code,
                        "minute_index": i,
                        "bar_index": row.get("bar_index"),
                        "dt10": row.get("dt10"),
                        "dt13": row.get("dt13"),
                        "dt19": row.get("dt19"),
                        "dt22": row.get("dt22"),
                        "dt23": row.get("dt23"),
                    }
                    for i, row in enumerate(rows)
                ]
            last_err = None
            break
        if last_err is not None:
            logger.warning(
                "BSE 历史分时 %s %s 重试后仍失败: %s", code, trade_date, last_err
            )
        return []

    def _bse_opening_auction(
        self,
        code: str,
        *,
        market: int,
        trade_date,
        timeout: float = 8.0,
    ) -> list[dict]:
        """北交所早盘竞价（09:15-09:25）逐笔：6144 平文本窗（当日/历史同协议）。

        失败时返回空表——竞价点是增强信息，不能阻塞分时主体。响应为
        0x003a 表（字段 1,10,49,27,33），与 7176 逐笔回放同一解析器。
        """
        from ..services.superorder import bse_tick_window

        day = trade_date if isinstance(trade_date, date_type) else date_type.today()
        cst = timezone(timedelta(hours=8))
        start_dt = datetime.combine(day, time_type(9, 15), tzinfo=cst)
        end_dt = datetime.combine(day, time_type(9, 25), tzinfo=cst)
        try:
            ticks = self._run_default_service(
                (),
                lambda: bse_tick_window(
                    self._timeline_service,
                    code,
                    market=market,
                    start_ts=int(start_dt.timestamp()),
                    end_ts=int(end_dt.timestamp()),
                    timeout=timeout,
                    tag=6144,
                    pageid=10444,
                    route=0x0100,
                    flag14=0x0000,
                    byte16=0x00,
                    byte17=0x18,
                ),
            )
        except Exception as exc:
            logger.info(
                "BSE 竞价窗 %s %s 获取失败（忽略，竞价段留空）: %s",
                code, day, exc,
            )
            return []
        rows = []
        for tick in ticks:
            ts = tick.get("ts")
            price = tick.get("price")
            if not ts or price is None:
                continue
            rows.append(
                {
                    "time": datetime.fromtimestamp(ts, cst),
                    "dt10": price,
                    "dt13": tick.get("volume") or 0,
                }
            )
        return rows

    def intraday_auctions(
        self,
        code: str,
        market: int = 0,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        """Return auction phases used to supplement the fast live timeline."""
        if market == 0:
            market = self._market_for_code(code)
        market = _intraday_market(market)
        # 北交所竞价协议未实现，不存在可补全的竞价段。
        if market == 151:
            return []
        value = trade_date
        if isinstance(value, str):
            value = date_type.fromisoformat(value)
        elif isinstance(value, datetime):
            value = value.date()
        elif value is None:
            value = latest_trade_date()
        service_trade_date = value if trade_date is None else trade_date

        # The staged web endpoint must provide the whole previous session
        # before today's 09:15 boundary and on non-trading days.  Otherwise
        # the fast live-timeline endpoint is intentionally empty and the
        # chart would contain only opening/closing auctions.
        if value != date_type.today():
            return self.intraday(
                code,
                market=market,
                trade_date=value,
                timeout=timeout,
            )
        profile = (
            self._service_connections.profile
            if self._service_connections is not None
            else self.observed_account_profile
        )
        if (
            profile.kind is AccountKind.LEVEL2
            and market not in (16, 32, 144, 151)
        ):
            return self._run_default_service(
                (
                    Capability.L2_AUCTION,
                    Capability.L2_HISTORY_TIMELINE,
                ),
                lambda: self._auction_service.intraday_auctions(
                    code,
                    market=market,
                    trade_date=service_trade_date,
                    timeout=timeout,
                ),
            )

        opening = self.auction(
            code,
            market=market,
            trade_date=service_trade_date,
            timeout=timeout,
        )
        closing = self.closing_auction(
            code,
            market=market,
            trade_date=service_trade_date,
            timeout=timeout,
        )
        return [
            *({"phase": "opening_auction", **row} for row in opening),
            *({"phase": "closing_auction", **row} for row in closing),
        ]

    def history_timeline(
        self,
        code: str,
        date,
        market: int = 0,
        timeout: float = 12.0,
        retries: int = 3,
        prev_close: float | None = None,
    ) -> list[dict]:
        """查**历史分时（回忆）**：某交易日的逐点分时行情（现价/量额/level2 大单）。

        个股按账号走 ``pageid=9355/4417``；指数走抓包一致的
        ``pageid=77``。日期游标编码由服务自动选择。

        **与当日分时的区别**：Level2 历史响应包含 201-230 大单字段；普通账号
        返回基础价量额字段，不虚构无权限字段。

        响应若为 ``cmd=0x0a`` 会先解开 8901 字典压缩；指数和个股块再按 241 点
        ``bar_index`` 序列锚定。请求固定走已实测成功的
        ``Level2 passport + 对应市场 L2 服务器 + init`` 通道，并与同一市场上的其他
        请求/读取严格串行。服务器偶发返回连 bar 高位也省略的强状态变体，
        解析器只返回可安全验证的点；``retries`` 不能代替完整状态机解码。

        Args:
            code: 股票代码（如 ``"000938"``；指数用 ``"1A0002"``）。
            date: 目标交易日（``date``/``datetime``/``"YYYY-MM-DD"`` 字符串）。
                必须是历史交易日（非当天，当天用 :meth:`timeline`）。
            market: 市场码（0=按代码前缀自动推断，含 1A/1B/399 指数）。
            timeout: 单次 read_frame 超时（秒）。
            retries: 连接失败时的重试次数（每次重连轮换 IP）。
            prev_close: 目标历史日的昨收；不传时自动查询日 K。

        Returns:
            记录列表，每条 ``{bar_index, dt10, dt13, dt19, dt22, dt23, ...}``。
            dt10=现价、dt13=成交量、dt19=成交额、dt201-230=level2 大单金额。
            指数记录额外包含 ``dt40`` 和还原后的 ``lead_price``（黄线）。
            指数和完整锚点型个股帧均可解；服务器确实缺少某个 bar 时保留其余有效点，
            不凭空补值。

        Raises:
            RuntimeError: 重试 ``retries`` 次后仍失败。
        """
        if market == 0:
            market = self._market_for_code(code)
        market = _intraday_market(market)
        last_err = ""
        for attempt in range(retries + 1):
            if (
                self._auth is None
                and self._service_connections is None
            ):
                logger.info(
                    "history_timeline: 尚未鉴权，仅获取 HTTP passport"
                    "（attempt %d/%d）",
                    attempt + 1,
                    retries + 1,
                )
                try:
                    self.authenticate()
                except Exception as exc:
                    last_err = f"HTTP 鉴权失败: {exc}"
                    continue
            try:
                profile = (
                    self._service_connections.profile
                    if self._service_connections is not None
                    else self.observed_account_profile
                )
                capability = (
                    Capability.BASIC_HISTORY_TIMELINE
                    if profile.kind is AccountKind.STANDARD
                    else Capability.L2_HISTORY_TIMELINE
                )
                records = self._run_default_service(
                    (capability,),
                    lambda: self._timeline_service.history_timeline(
                        code,
                        market=market,
                        date=date,
                        timeout=timeout,
                    ),
                )
                if records:
                    if market in (16, 32, 144):
                        target_date = date
                        if isinstance(target_date, str):
                            target_date = date_type.fromisoformat(target_date)
                        elif isinstance(target_date, datetime):
                            target_date = target_date.date()
                        records = self._enrich_index_timeline(
                            records,
                            code,
                            market=market,
                            target_date=target_date,
                            prev_close=prev_close,
                            timeout=timeout,
                        )
                    return records
                last_err = "收到强状态省略帧或未找到历史分时数据"
                logger.info(
                    "history_timeline %s %s 未获得可验证变体，重请求（attempt %d/%d）",
                    code, date, attempt + 1, retries + 1,
                )
            except (ConnectionError, OSError, TimeoutError) as e:
                last_err = f"{type(e).__name__}: {e}"
                logger.warning("history_timeline %s %s 失败（attempt %d）: %s",
                               code, date, attempt + 1, last_err)
                if capability is Capability.BASIC_HISTORY_TIMELINE:
                    if self._service_connections is not None:
                        self._service_connections.close(
                            ConnectionRole.MAIN
                        )
                    self._drop_connection()
                    continue
                key = pick_l2_market(market)
                with self._push_lock:
                    failed = self._push_socks.pop(key, None)
                    self._push_initialized.discard(key)
                role = (
                    ConnectionRole.SH_L2
                    if key == "sh"
                    else ConnectionRole.SZ_L2
                )
                if self._service_connections is not None:
                    self._service_connections.close(role)
                if failed is not None:
                    try:
                        failed.close()
                    except OSError:
                        pass
        raise RuntimeError(f"history_timeline {code} {date} 重试 {retries} 次仍失败: {last_err}")

    def dde_rank(
        self,
        count: int = 58,
        timeout: float = 10.0,
        with_names: bool | str = False,
        sort_by: int = 592888,
        sort_dir: str = "D",
        max_pages: int = 120,
    ) -> list[dict]:
        """Return the desktop DDE page ranking (pageid=10723).

        Standard accounts use the combined MAIN request.  Level2 accounts use
        the captured SH/SZ split routes and the two server rankings are merged
        globally by their decoded numeric value.

        Each row contains ``code``, ``market``, ``value``, ``sort_by`` and
        ``response_field``.  Verified DDE sort keys are 592888 (default main
        force), 592890 (main-force net inflow), plus the captured table keys
        199112, 19, 48 and 1968584.
        """
        self._ensure_main_connection()
        capability = (
            Capability.L2_MARKET_ACCESS
            if self.observed_account_profile.kind is AccountKind.LEVEL2
            else Capability.BASIC_QUOTE
        )
        # 页面刷新时 ranked 全量/quotes_ext 资金请求与本接口在同一对 L2 连接上
        # 并发竞争，偶发超时（实测隔次恢复）：失败重试一次。
        try:
            rows = self._run_default_service(
                (capability,),
                lambda: self._stock_list_service.dde_ranked(
                    count=count,
                    timeout=timeout,
                    sort_by=sort_by,
                    sort_dir=sort_dir,
                    max_pages=max_pages,
                ),
            )
        except (OSError, ProtocolError) as exc:
            logger.warning("dde_rank: 首次失败(%s)，重试一次", exc)
            rows = self._run_default_service(
                (capability,),
                lambda: self._stock_list_service.dde_ranked(
                    count=count,
                    timeout=timeout,
                    sort_by=sort_by,
                    sort_dir=sort_dir,
                    max_pages=max_pages,
                ),
            )
        if with_names and rows:
            name_map = self.fetch_stock_names_full()["names"]
            for row in rows:
                name = name_map.get(row["code"], "")
                if name:
                    row["name"] = name
        return rows

    def stock_list_hot(
        self,
        count: int = 29,
        timeout: float = 10.0,
        with_names: bool | str = False,
        sort_by: int = 199112,
        sort_dir: str = "D",
        max_pages: int = 120,
        with_values: bool = False,
    ) -> list[dict]:
        """获取排序榜单（自动翻页，可拿完整榜单）。

        发送排序代码表查询（同花顺打开 A 股列表、切换排序列时发的请求），
        服务器按 ``sort_by`` 指定的字段排序后返回。本方法自动用 SortBegin 游标
        翻页，直到拿满 ``count`` 条或取完整个榜单。

        ``sort_by`` 是排序键编号（见 :data:`protocol.SORT_BY_VALUES`，均为活网验证）：
        涨幅=199112(响应 dt200)、涨速=48、换手率=1968584、量比=1771976、
        主力净流入=592890、竞价金额=68758(响应 dt150)、竞价涨幅=68762、
        封单额=265260(响应 dt44)。默认按涨幅降序（涨幅榜）。
        换成跌幅榜传 ``sort_by=199112, sort_dir="A"``（升序值 A 为推测，未实测）。
        封单额榜 ``sort_by=265260`` 是服务端排序（不是查所有盘口本地排），
        全市场约 2899 只参与，非涨停股封单额为 0 排在末尾。
        dt200/dt150/dt44 经 ``tests/verify_sort_values_online.py`` 活网验证。

        成交额榜 ``sort_by=19``（响应 dt19 元）/成交量榜 ``sort_by=13``（dt13 股）
        于 2026-08-19 在 L2 排序路径活网验证可用。旧结论"成交量/成交额不能
        SortBy"仅适用于早期普通账号观察（客户端确实也用推送本地排，见
        docs/handoffs/HANDOFF_STOCKLIST_PUSH.md），L2 服务端排序本身支持。

        翻页机制（2026-07-23 抓包确认）：SortBegin 是游标（首次 0，翻页递增到
        已加载位置），每页 59 条（SortCount 恒 59）。``count`` 是想要的总条数，
        本方法内部循环请求直到拿满。

        Args:
            count: 想要的总条数，默认 29（对齐 hexin 第一页，向后兼容）。
                想要完整榜单（约 5200 条）传一个大数如 5300 即可。
            timeout: 单次请求的超时时间（秒）。
            with_names: 是否填充中文名称（同 stock_list 的 with_names 参数）。
            sort_by: 排序键编号，默认 199112（涨幅）。见
                :data:`protocol.SORT_BY_VALUES`。
            sort_dir: 排序方向，``"D"``=降序（默认）、``"A"``=升序（推测，未实测）。
            max_pages: 翻页安全阀（默认 120，≈5300/59），防止死循环。
            with_values: 是否保留响应里的 ``dt<N>`` 数值字段（默认 False，只返回
                code/name/market）。传 True 时每项额外含排序值等 dt 字段，免去
                之后走 :meth:`list_quotes` 回填。已活网验证的响应字段：涨幅 dt200、
                竞价金额 dt150、封单额 dt44（见 ``tests/verify_sort_values_online.py``）。

        Returns:
            list[dict]，每项 ``{"code": "600519", "name": "贵州茅台"}``；
            ``with_values=True`` 时额外含 ``dt<N>`` 字段。按 code 去重（页边界
            可能重叠）。

        Raises:
            RuntimeError: 未登录。
        """
        self._ensure_main_connection()
        # 2026-08-14 客户端抓包确认：Level2 排序榜拆 SH_L2/SZ_L2 两条连接
        # （pageid=1341），普通账号走 MAIN 单请求（pageid=1334）。授权
        # capability 与 dde_rank 同理按账号类型选择。
        capability = (
            Capability.L2_MARKET_ACCESS
            if self.observed_account_profile.kind is AccountKind.LEVEL2
            else Capability.BASIC_QUOTE
        )
        stocks = self._run_default_service(
            (capability,),
            lambda: self._stock_list_service.ranked(
                count=count,
                timeout=timeout,
                sort_by=sort_by,
                sort_dir=sort_dir,
                max_pages=max_pages,
                with_values=with_values,
            ),
        )
        stocks = self._anchor_correct_money_sort(
            stocks, sort_by=sort_by, sort_dir=sort_dir,
            with_values=with_values, timeout=timeout,
        )
        if with_names and stocks:
            name_map = self.fetch_stock_names_full()["names"]
            for stock in stocks:
                name = name_map.get(stock["code"], "")
                if name:
                    stock["name"] = name
        return stocks

    # 金额类排序键 → (榜单值字段, 0xc4 锚定取值函数名)。
    # 2026-08-20 实测 L2 排序(592890)注入真值×100 的虚值行（见
    # services.stock_list._anchor_correct_ranked_values），其他金额键同理
    # 可能中招；封单额 265260 的 dt44 不在 0xc4 表内、无法锚定，跳过。
    _MONEY_SORT_ANCHORS: dict[int, tuple[str, str]] = {
        592890: ("dt250", "main_inflow"),
        19: ("dt19", "amount"),
        13: ("dt13", "dt13"),
        68758: ("dt150", "auction_amount"),
    }

    # 可全表锚定的键 → 直查真值的轻量 DataType（400 码/批）。
    # 68758 竞价金额：L2 大 SortCount 响应在整张表混入 ×1e4/×1e6/×1e8 的
    # dt150，只校正头 120 行会让下一批虚值在重排后再次冒到榜首，必须全表
    # 锚定（dt17×dt7 从 [5,7,17] 小表直查）。19 成交额同理（2026-09-04
    # 全榜乱序实测）：标准列表表 [5,19] 直接回真值 dt19；此前走 0xc4 大表
    # 没有 dt19，dt13×dt10 只是 vwap≈现价的近似，±0.1% 的倍率窗永远匹配
    # 不上，校正静默失效（0xc4 大表还易与页面轮询抢 MAIN 超时）。
    _LIGHT_ANCHOR_DATATYPES: dict[int, list[int]] = {
        68758: [5, 7, 17],
        19: [5, 19],
    }

    # 全表锚定的批次流量缓存 TTL（秒）。排行榜每 5s 轮询一次，全表锚定
    # 每次要在 MAIN 上打 ~14 批 list_quotes，开盘高峰与 quotes_ext 抢
    # 连接导致 dispatcher 超时→重连风暴，盘口/短线精灵被拖死
    # （2026-09-04 13:00 开盘实测）。锚点只用于识别 ×10^2k 的倍率量级，
    # 数值小幅滞后不影响校正正确性：68758 竞价金额开盘后全天不变给 300s；
    # 19 成交额日内缓慢增长给 30s。0xc4 榜首 120 行锚定流量小，不缓存。
    _MONEY_ANCHOR_TTL: dict[int, float] = {
        68758: 300.0,
        19: 30.0,
    }

    def _anchor_correct_money_sort(
        self,
        stocks: list[dict],
        *,
        sort_by: int,
        sort_dir: str,
        with_values: bool,
        timeout: float,
    ) -> list[dict]:
        """用独立行情真值锚定校正金额类排序的缩放虚值。"""
        anchor = self._MONEY_SORT_ANCHORS.get(sort_by)
        if not anchor or not with_values or not stocks:
            return stocks
        ranked_field, derive_key = anchor
        # 68758/19 的轻量表可全表锚定（虚值不止出现在榜首 120 行）；
        # 其他 0xc4 金额键响应更大，仍只检查最可能污染榜首的 120 行。
        light_datatype = self._LIGHT_ANCHOR_DATATYPES.get(sort_by)
        candidates = stocks if light_datatype is not None else stocks[:120]
        codes_to_anchor = [
            str(r.get("code", "")) for r in candidates if r.get("code")
        ]
        if not codes_to_anchor:
            return stocks
        from ..features.quote_protocol import (
            MONEY_QUOTE_DATATYPE,
            derive_list_quote_fields,
        )
        from ..services.stock_list import _anchor_correct_ranked_values

        ttl = self._MONEY_ANCHOR_TTL.get(sort_by)
        anchor_cache = getattr(self, "_money_anchor_cache", None)
        if anchor_cache is None:
            anchor_cache = self._money_anchor_cache = {}
        anchors: dict[str, float] | None = None
        cached = anchor_cache.get(sort_by) if ttl else None
        if cached is not None and time.monotonic() - cached[0] < ttl:
            anchors = cached[1]
        if anchors is None:
            groups: dict[int, list[str]] = {}
            for code in codes_to_anchor:
                groups.setdefault(self._market_for_code(code), []).append(code)
            anchors = {}
            datatype = light_datatype or MONEY_QUOTE_DATATYPE
            batch_size = 400 if light_datatype is not None else 40
            for market, codes in groups.items():
                for i in range(0, len(codes), batch_size):
                    chunk = codes[i : i + batch_size]
                    try:
                        records = self.list_quotes(
                            chunk,
                            market=market,
                            datatype=datatype,
                            pageid=1334,
                            timeout=timeout,
                        )
                    except (ProtocolError, OSError) as exc:
                        logger.warning(
                            "money sort 锚定批失败 market=%s: %s", market, exc
                        )
                        continue
                    for record in records:
                        code = str(record.get("code", ""))
                        if not code:
                            continue
                        if derive_key in (
                            "main_inflow", "amount", "auction_amount",
                        ):
                            value = derive_list_quote_fields(record).get(
                                derive_key
                            )
                        else:
                            value = record.get(derive_key)
                        if isinstance(value, (int, float)):
                            anchors[code] = value
            # 覆盖率达标才缓存：部分市场组失败时保留旧行为（下轮重试），
            # 不把残缺锚点钉死一个 TTL 周期。
            if (
                ttl
                and anchors
                and len(anchors) >= len(codes_to_anchor) * 0.9
            ):
                anchor_cache[sort_by] = (time.monotonic(), anchors)
        if not anchors:
            return stocks
        stocks, corrected = _anchor_correct_ranked_values(
            stocks,
            ranked_field=ranked_field,
            anchors=anchors,
            sort_dir=sort_dir,
        )
        if sort_by == 68758:
            # 给 Web 一个明确的“已校准”字段。旧后端只返回原始 dt150，前端
            # 绝不能把它当真值显示，否则热更新期间会出现几万亿。
            for stock in stocks:
                value = stock.get(ranked_field)
                if isinstance(value, (int, float)):
                    stock["auction_amount"] = value
        if corrected:
            logger.warning(
                "money sort sort_by=%s 锚定校正 %d 行（服务端缩放虚值）",
                sort_by, corrected,
            )
        return stocks

    def stock_list(
        self,
        timeout: float = 30.0,
        with_names: bool | str = False,
    ) -> list[dict]:
        """获取全市场股票代码列表（沪深+北交所+新三板+基金，~7400 条）。

        登录/init 后发送一个 ``DataType=[5],[55]`` 空市场组查询，触发服务器
        下发全量代码/名称表。主动 A/B 已确认旧抓包里的 153 个 subreal、1B0987、
        重复 init 和其他查询均非必需。

        Args:
            timeout: 收尾读取的总时长（秒）。请求后服务器陆续推送，需等全量帧到达。
            with_names: 是否填充中文名称。
                - False: 不填名称（默认，快）
                - True: fetch names via 123ths network sync (cross-platform)
                - str: ignored (names are network-backed)

        Returns:
            list[dict]，每项 ``{"code": "600000", "name": "浦发银行"}``。
            约 7400 条，按 dt5 代码字段顺序（通常代码升序）。
            with_names=False 时 name 恒为 ""。

        Raises:
            RuntimeError: 未登录。
        """
        self._ensure_main_connection()
        capabilities: tuple[Capability, ...] = (Capability.BASIC_QUOTE,)
        if self.observed_account_profile.kind is AccountKind.LEVEL2:
            # Level2 的深市代码表在 SZ_L2（szlv2）：乐观租借
            # L2_MARKET_ACCESS 让 full_list 能开 SZ 通道合并深市表。
            capabilities = (Capability.BASIC_QUOTE, Capability.L2_MARKET_ACCESS)
        stocks = self._run_default_service(
            capabilities,
            lambda: self._stock_list_service.full_list(timeout=timeout),
        )
        if with_names and stocks:
            name_map = self.fetch_stock_names_full()["names"]
            for stock in stocks:
                name = name_map.get(stock["code"], "")
                if name:
                    stock["name"] = name
        return stocks

    def market_snapshot(
        self,
        markets: list[int] | None = None,
        timeout: float = 10.0,
    ) -> list[dict]:
        """全市场代码名称快照：一个请求拿沪市全市场 code+name（~0.13s）。

        在 :meth:`connect` 建立的**主连接**上发 hfd1.0 空括号请求
        （``CodeList=16();17();...``），服务器一次性返回整个市场的股票代码和
        名称。相比 :meth:`list_quotes` 逐批查询（~250 请求），本方法只需 1 个请求，
        速度提升 2~3 个数量级。

        当前请求固定使用 ``DataType=[5],[55]``，响应不含 price/change_pct 等
        行情字段。对于准确行情请用 :meth:`list_quotes`（或
        :meth:`market_snapshot_with_quotes` 的混合方案）。

        ⚠️ 当前连接的服务器 host **可能不支持 hfd1.0**（集群中仅部分 host 支持）。
        不支持时本方法返回空列表——但**不重连**（重连会触发 VerifyCode=-1，
        见 docs/handoffs/HANDOFF.md §7）。需要稳定拿沪市行情时优先用
        :meth:`market_snapshot_with_quotes`。

        Args:
            markets: 市场码列表，None 用 :data:`MARKET_SNAPSHOT_MARKETS`
                （16-22/144-151 沪市全）。
            timeout: 单次 read_frame 超时（秒）。

        Returns:
            list[dict]，每项含 ``code``、``name`` 和名称原始偏移，
            约 1200+ 条（当前锚点覆盖率）。host 不支持或超时返回 []。

        Raises:
            RuntimeError: 未登录（self._sock 为空）。
        """
        self._ensure_main_connection()
        return self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._market_snapshot_service.snapshot(
                markets=markets,
                timeout=timeout,
            ),
        )

    def snapshot_subscribe(
        self,
        code: str,
        market: int | None = None,
        callback=None,
    ) -> bool:
        """订阅个股实时逐 tick 快照推送（现价随每笔成交跳动）。

        在对应市场 L2 服务器上开一条独立的 8901 连接，发 pageid=4214 订阅帧
        （嵌套双子帧），服务端持续推送 71B 快照帧（约每 3 秒，盘中全程不断）。

        2026-07-29 PC 抓包确认该 L2 连接使用 ``thsuser`` 标准行情登录壳，
        Level2 passport + 正确的 shlv2/szlv2 路由和市场 init 才决定 4214 注册能力。

        ⚠️ 需要 **level2 账号**：普通账号打开分时走 pageid=9355（请求-响应，无推送）。
        ⚠️ 需在**盘中**（9:30-15:00）才有逐笔成交推送；收盘后注册成功但无推送数据。

        推送连接独立于主连接（``self._sock``），不影响 kline/list_quotes 等
        请求-响应方法。推送数据由后台线程读取并解析，两种消费方式：
          - ``callback``：每收到一帧调用 ``callback(code, market, price, volume)``
          - 无 callback 时存入 ``self._latest_price[code]``，用 ``latest_price()`` 取

        Args:
            code: 股票代码（纯数字，如 ``"000938"``）。
            market: 市场码（17=沪 33=深）。None 时按代码推导（6开头=沪17，其余=深33）。
            callback: 可选回调 ``fn(code:str, market:str, price:float, volume:int)``。

        Returns:
            True=订阅请求已发送（CodeListSize≥1）；False=注册失败或未登录。
        """
        try:
            market = self._register_l2_snapshot_code(code, market=market)
        except ProtocolError as exc:
            logger.warning(
                "snapshot_subscribe: %s 注册失败: %s",
                code,
                exc,
            )
            return False
        else:
            self._activate_snapshot_subscription(code, market, callback)
            return True

    def _register_l2_snapshot_code(
        self,
        code: str,
        *,
        market: int | None,
    ) -> int:
        """Register one code on its market L2 channel and return market code."""
        if market in (None, 0):
            market = self._market_for_code(code)
        # 北交所（151）没有 shlv2/szlv2 式 L2 通道，pick_l2_market 不接受 151；
        # 十档面板对 BSE 本就无数据（走 10443 五档字段，尚未实现），
        # stock-ready 门禁直接返回市场码，不再抛 500。
        if market == 151:
            return market
        key = pick_l2_market(market)
        if self._auth is None and self._service_connections is None:
            self.authenticate()

        def register() -> bool:
            role = ConnectionRole.SH_L2 if key == "sh" else ConnectionRole.SZ_L2
            connection = self._service_connections.acquire(
                role,
                capability=Capability.L2_SNAPSHOT_PUSH,
            )
            self._service_subscriptions.ensure_registered(
                connection,
                code,
                market=market,
                timeout=5.0,
            )
            return True

        self._run_default_service(
            (Capability.L2_SNAPSHOT_PUSH,),
            register,
        )
        return market

    def depth_subscribe(
        self,
        code: str,
        market: int | None = None,
        callback=None,
    ) -> bool:
        """订阅一只股票的 Level2 十档盘口事件。

        复用 :meth:`snapshot_subscribe` 的 4214 L2 注册和同一后台读取线程，但
        深度事件使用独立消费接口：``callback(record)``、:meth:`receive_depth`
        或 :meth:`latest_depth`。一帧携带多只股票时会逐条完整分发，不再只取首条。

        同一客户端可重复调用本方法订阅沪深多只股票；相同代码只发送一次注册帧。
        普通账号和能力未知账号沿用 ``L2_SNAPSHOT_PUSH`` 的显式拒绝语义。
        """
        try:
            market = self._register_l2_snapshot_code(code, market=market)
        except ProtocolError as exc:
            logger.warning("depth_subscribe: %s 注册失败: %s", code, exc)
            return False
        self._connection_runtime.activate_depth(code, market, callback)
        return True

    def market_events_subscribe(
        self,
        code: str,
        market: int | None = None,
        callback=None,
    ) -> bool:
        """Subscribe to normalized trade/depth/queue/cancel events.

        This reuses the same 4214 registration, market L2 socket and reader as
        :meth:`depth_subscribe`; it never creates another THSClient or login.
        """
        try:
            market = self._register_l2_snapshot_code(code, market=market)
        except ProtocolError as exc:
            logger.warning("market_events_subscribe: %s 注册失败: %s", code, exc)
            return False
        self._connection_runtime.activate_market_events(
            code,
            market,
            callback,
        )
        return True

    def market_events_prepare(
        self,
        code: str,
        market: int | None = None,
    ) -> int:
        """Register *code* on its existing L2 lane without starting a reader.

        The web stock-switch gate calls this once before depth, timeline,
        superorder and WebSocket consumers fan out.  The connection-scoped
        coordinator makes repeated calls idempotent; no new client, socket or
        Passport is created.
        """
        return self._register_l2_snapshot_code(code, market=market)

    def ranking_depth_subscribe(
        self,
        codes,
        *,
        market: int | None = None,
        callback=None,
        query_datatype=RANKING_LIST_DATATYPE,
        timeout: float = 5.0,
    ) -> int:
        """Register a page-982 ranking CodeList on an existing L2 lane.

        This is the bulk counterpart to :meth:`depth_subscribe`.  It reuses the
        same managed SH_L2/SZ_L2 socket and depth reader; it never performs a
        second login.  The default field query matches the official client's
        2026-08-19 ``0x5f`` ranking capture.

        Returns the server's acknowledged ``CodeListSize``.  Live delivery is
        consumed through :meth:`receive_depth`, :meth:`latest_depth`, or the
        per-record callback.
        """
        raw_codes = (codes,) if isinstance(codes, str) else codes
        normalized = tuple(
            dict.fromkeys(
                str(code).strip() for code in raw_codes if str(code).strip()
            )
        )
        if not normalized or any(not code.isdigit() for code in normalized):
            raise ValueError("codes 必须包含至少一个纯数字股票代码")
        if market is None:
            inferred = {17 if code.startswith("6") else 33 for code in normalized}
            if len(inferred) != 1:
                raise ValueError("沪深代码必须按市场分别调用 ranking_depth_subscribe")
            market = inferred.pop()
        key = pick_l2_market(market)
        wire_market = 17 if key == "sh" else 33

        def register() -> int:
            role = ConnectionRole.SH_L2 if key == "sh" else ConnectionRole.SZ_L2
            connection = self._service_connections.acquire(
                role,
                capability=Capability.L2_SNAPSHOT_PUSH,
            )
            size = self._list_bucket_service.replace_codes(
                connection,
                {wire_market: normalized},
                command=RANKING_LIST_COMMAND,
                pageid=RANKING_LIST_PAGEID,
                timeout=timeout,
            )
            if query_datatype:
                wire_seq = self._next_request_instance() & 0xFFFF or 1
                self._list_bucket_service.query(
                    connection,
                    {wire_market: normalized},
                    query_datatype,
                    command=RANKING_LIST_COMMAND,
                    pageid=RANKING_LIST_PAGEID,
                    wire_seq=wire_seq,
                    timeout=timeout,
                )
            for code in normalized:
                self._connection_runtime.activate_ranking_depth(
                    code,
                    wire_market,
                    callback,
                )
            return size

        return self._run_default_service(
            (Capability.L2_SNAPSHOT_PUSH,),
            register,
        )

    def ranking_depth_update(
        self,
        *,
        add=(),
        remove=(),
        market: int,
        callback=None,
        query_datatype=RANKING_LIST_DATATYPE,
        timeout: float = 5.0,
    ) -> int:
        """Apply the captured mode-5 ranking delta on the existing L2 lane."""
        raw_add = (add,) if isinstance(add, str) else add
        raw_remove = (remove,) if isinstance(remove, str) else remove
        add_codes = tuple(dict.fromkeys(str(code).strip() for code in raw_add))
        remove_codes = tuple(dict.fromkeys(str(code).strip() for code in raw_remove))
        if not add_codes and not remove_codes:
            raise ValueError("add/remove 不能同时为空")
        if any(not code.isdigit() for code in (*add_codes, *remove_codes)):
            raise ValueError("add/remove 只能包含纯数字股票代码")
        key = pick_l2_market(market)
        wire_market = 17 if key == "sh" else 33

        def update() -> int:
            role = ConnectionRole.SH_L2 if key == "sh" else ConnectionRole.SZ_L2
            connection = self._service_connections.acquire(
                role,
                capability=Capability.L2_SNAPSHOT_PUSH,
            )
            size = self._list_bucket_service.apply_delta(
                connection,
                command=RANKING_LIST_COMMAND,
                pageid=RANKING_LIST_PAGEID,
                add={wire_market: add_codes} if add_codes else {},
                remove={wire_market: remove_codes} if remove_codes else {},
                timeout=timeout,
            )
            if add_codes and query_datatype:
                wire_seq = self._next_request_instance() & 0xFFFF or 1
                self._list_bucket_service.query(
                    connection,
                    {wire_market: add_codes},
                    query_datatype,
                    command=RANKING_LIST_COMMAND,
                    pageid=RANKING_LIST_PAGEID,
                    wire_seq=wire_seq,
                    timeout=timeout,
                )
            for code in add_codes:
                self._connection_runtime.activate_ranking_depth(
                    code,
                    wire_market,
                    callback,
                )
            for code in remove_codes:
                self._connection_runtime.deactivate_ranking_depth(code)
            return size

        return self._run_default_service(
            (Capability.L2_SNAPSHOT_PUSH,),
            update,
        )

    def ranking_depth_clear(
        self,
        *,
        market: int,
        timeout: float = 5.0,
    ) -> int:
        """Clear the page-982 ranking bucket and local depth deliveries."""
        key = pick_l2_market(market)
        role = ConnectionRole.SH_L2 if key == "sh" else ConnectionRole.SZ_L2
        manager = self._service_connections
        if manager is None:
            return 0
        connection = manager.peek(role)
        if connection is None or self._list_bucket_service is None:
            return 0
        size, prior = self._list_bucket_service.clear(
            connection,
            command=RANKING_LIST_COMMAND,
            pageid=RANKING_LIST_PAGEID,
            timeout=timeout,
        )
        for code in prior:
            self._connection_runtime.deactivate_ranking_depth(code)
        return size

    def depth_unsubscribe(self, code: str, *, clear_latest: bool = True) -> bool:
        """停止一只股票的本地十档事件交付。

        现有抓包尚未确认 4214 的单码退订帧，因此还有其他订阅时仅移除本地回调、
        队列交付和缓存；最后一个快照/深度消费者退出时关闭后台线程及 L2 通道。
        返回该代码在调用前是否处于深度订阅状态。
        """
        return self._connection_runtime.deactivate_depth(
            code,
            clear_latest=clear_latest,
        )

    def market_events_unsubscribe(self, code: str) -> bool:
        """Stop normalized market-event delivery for one code."""
        return self._connection_runtime.deactivate_market_events(code)

    def receive_depth(self, timeout: float | None = None) -> dict | None:
        """读取下一条已订阅十档事件；超时返回 ``None``。"""
        return self._connection_runtime.receive_depth(timeout)

    def receive_market_event(self, timeout: float | None = None) -> dict | None:
        """Read the next normalized event for active market subscriptions."""
        return self._connection_runtime.receive_market_event(timeout)

    def latest_price(self, code: str) -> float | None:
        """取某代码的最新现价（snapshot_subscribe 后由推送线程更新）。"""
        return self._latest_price.get(code)

    def latest_depth(self, code: str) -> dict | None:
        """取某代码的最新十档盘口（549B 推送解析结果）。

        返回 ``parse_depth_push`` 的 dict（含 price/prev_close/open/high/low/
        bids[10]/asks[10]），或 None。需先 ``depth_subscribe`` 且盘中服务器
        推送了十档帧。
        """
        return self._latest_depth.get(code)

    def stop_snapshot(self) -> None:
        """停止分时推送读取线程，关闭沪深两条 L2 推送连接（disconnect 时自动调用）。"""
        self._connection_runtime.stop_snapshot()

    def dxjl_page(self, market: int, endtime_us: int) -> list[dict]:
        """获取短线精灵单页数据（9601，method=qurealorder）。

        Args:
            market: 市场代码，32=深 16=沪。
            endtime_us: 微秒时间戳游标（取此时间之前的记录）。

        Returns:
            list[dict]，每项含 时间(微秒戳)/市场/代码/异动类型/异动编码/金额/涨跌幅。
        """
        return self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._realorder_service.dxjl_page(
                market,
                endtime_us,
            ),
        )

    def _attach_dxjl_names(self, records: list[dict]) -> list[dict]:
        """为短线精灵记录回填 名称（当日缓存的代码-名称表，热路径无网络）。

        尽力而为：名称表不可用（未登录 123ths/网络失败）时返回原记录，
        前端回退显示代码。
        """
        if not records:
            return records
        try:
            name_map = self.fetch_stock_names_full()["names"]
        except Exception:
            logger.debug("dxjl 名称回填跳过：名称表不可用", exc_info=True)
            return records
        for record in records:
            name = name_map.get(record.get("代码", ""))
            if name:
                record["名称"] = name
        return records

    def dxjl_latest(self, markets: tuple = (32, 16)) -> list[dict]:
        """获取短线精灵最新一页（沪深）。

        Args:
            markets: 市场元组，默认 (32, 16) = 深沪。

        Returns:
            list[dict]，按时间倒序（最新在前），含 名称。非交易时段可能为空。
        """
        records = self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._realorder_service.dxjl_latest(markets=markets),
        )
        return self._attach_dxjl_names(records)

    def dxjl_history(
        self,
        pages: int = 5,
        markets: tuple = (32, 16),
        endtime_us: int | None = None,
    ) -> list[dict]:
        """翻页获取短线精灵历史数据（endtime 游标分页）。

        翻页机制：第 N+1 页的 endtime = 第 N 页最早记录的时间戳。

        Args:
            pages: 翻页数。
            markets: 市场元组，默认 (32, 16) = 深沪。
            endtime_us: 起始游标（微秒时间戳）。None=从当前时刻向前翻；
                前端上拉加载历史时传已加载最早一条的时间。

        Returns:
            list[dict]，按时间倒序，含 名称。
        """
        records = self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._realorder_service.dxjl_history(
                pages=pages,
                markets=markets,
                now_us=endtime_us,
            ),
        )
        return self._attach_dxjl_names(records)

    def subscribe_realtime(self, markets: list[int] | None = None) -> None:
        """在 9601 上订阅异动推送（method=subrealorder）。

        订阅后服务器在盘中主动推送 pushrealorder 帧（实测约 1500 条异动/分钟）。
        用 receive_pushes() 接收推送数据。

        抓包确认（2026-07-17 hexin stream 9）：在 9601 发 subrealorder，
        market=16/32/151/48，服务器 90s 内推 1125 个 pushrealorder 帧。

        Args:
            markets: 市场代码列表，默认 [16,32,151,48]（沪/深/北交所/板块）。
        """
        self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._realorder_service.subscribe_realtime(markets),
        )

    def receive_pushes(self, timeout: float = 10.0,
                       callback=None) -> list[dict]:
        """接收 9601 实时推送（阻塞循环，直到 timeout）。

        需先 subscribe_realtime() 订阅。盘中会持续收到 pushrealorder 帧，
        每帧含 1~8 条异动记录（代码 + 原始字节）。

        推送从 9601 短线精灵连接接收。注意：9601 用 read_frame_realorder
        （len-1 编码，不同于 8901 的 read_frame）。

        Args:
            timeout: 接收时长（秒）。到时间后返回。
            callback: 若给定，每收到一条记录回调 ``callback(record_dict)``（实时处理）。
                      若为 None，收集所有记录到列表返回（批量模式）。

        Returns:
            list[dict]，每项 ``{代码, 市场, raw_bytes}``。callback 模式下返回空列表。
            非交易时段返回空列表（无推送）。
        """
        records, _ = self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._realorder_service.receive_pushes(
                timeout=timeout,
                callback=callback,
            ),
        )
        return records

    def receive_pushes_locked(self, timeout: float = 5.0,
                              callback=None, full_frame_callback=None) -> int:
        """带锁接收 9601 推送，可安全穿插历史查询（与 receive_pushes 的区别）。

        receive_pushes 直接读 socket 不持锁，若同时另一线程调 dxjl_page
        （持 _realorder_lock 读同一 socket）或心跳线程写 socket，会产生
        帧错位/数据竞争。本方法全程持 _realorder_lock，每收到一帧后**短暂
        释放再重获锁**，给心跳线程写入的机会（心跳 30s 周期，不会饿死）。

        配合 dxjl_history 在调用方交替使用（见 tests/collect_push_samples.py）：
        推送 N 秒（本方法）→ 释放锁后 dxjl_history 翻页 → 再推送 → …
        两者串行，不并发读同一 socket。

        Args:
            timeout: 本次接收时长（秒）。建议 ≤ 5s，避免长时间独占锁。
            callback: 每条解析记录回调 ``callback(rec_dict)``。
            full_frame_callback: 每个完整推送帧回调 ``cb(frame_bytes)``，
                用于离线逆向（保留 hq1.0 字段表头）。

        Returns:
            本次收到的推送帧数（不含心跳/其他帧）。
        """
        _, frame_count = self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._realorder_service.receive_pushes(
                timeout=timeout,
                callback=callback,
                full_frame_callback=full_frame_callback,
                continue_on_timeout=True,
            ),
        )
        return frame_count

    # ── 系统板块网络查询（板块专用通道 fu4 8901）──

    def hot_boards(
        self,
        codes: list[str] | None = None,
        *,
        timeout: float = 40.0,
    ) -> list[dict]:
        """热点板块（94 页面）行情，pageid=12480。

        2026-08-07 双账号抓包确认：94 热点板块与板块列表（392/5716）共用
        同一批 fu4 板块通道连接，仅组件路由不同（普通 0x003A/0x013A、L2
        0x0053/0x0153）。返回字段含 ``code``/``pre_close``/``price``/
        ``chg_pct``（dt6/dt10）、``limit_up``（dt15 涨停数）、``up_count``
        （dt38 涨家数）、``down_count``（dt39 跌家数）、``speed_4m``
        （dt48 4分钟涨速）、``speed_1m``（dt167）、``main_inflow``
        （dt250 主力净流入）。

        Args:
            codes: 板块指数代码列表；传 ``None`` 表示按全量板块代码表发送。
            timeout: 板块通道查询总超时（秒）。

        Returns:
            list[dict]，每条含 ``code``/``pre_close``/``price``/``chg_pct``
            /``limit_up``/``up_count``/``down_count``/``speed_4m`` 等字段。

        Raises:
            RuntimeError: 未登录或板块通道建连失败。
        """
        records = self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._board_service.hot_boards(
                codes,
                timeout=timeout,
            ),
        )
        # 94 页面的板块行情响应只有 code + 数值，不含名称。板块名称在
        # name_48 组缓存里（882/885/886 等概念指数），从当日名称组补全，
        # 避免前端只靠本地 industry.ini（只能覆盖 90 个 881 行业板块）。
        if records:
            try:
                name_map = self.fetch_stock_names_full()["names"]
            except Exception as exc:
                logger.warning("hot_boards: 板块名称补全失败: %s", exc)
            else:
                for record in records:
                    if not record.get("name"):
                        name = name_map.get(str(record.get("code", "")), "")
                        if name:
                            record["name"] = name
        return records

    def hot_boards_sorted(
        self,
        sort_by: int,
        *,
        codes: list[str] | None = None,
        sort_dir: str = "D",
        sort_begin: int = 0,
        sort_count: int = 26,
        timeout: float = 40.0,
    ) -> list[dict]:
        """热点板块表头排序，返回按列排序后的 (code, value) 记录。

        2026-08-07 排序抓包确认：点击板块表头即发 ``SortType=Sort`` +
        ``SortBy=<该列字段>``（subtype=0x000f），响应为 ``method=sort``
        + hd3.1 表（dt5 代码 + **dt<SortBy>** 排序字段值）。``sort_by``
        取值与排序字段：
        - ``199112`` 涨幅 → dt200（ZHANGDIEFU）
        - ``527527`` 1分钟涨速 → dt167（onerise）
        - ``592890`` 主力净流入 → dt250（bigtrademoneynow）
        - ``271`` 涨停数 → dt15；``38`` 涨家数 → dt38；``39`` 跌家数 → dt39

        Args:
            sort_by: 排序列字段编号（见上）。
            codes: 排序 universe（``None``=全量板块代码表）。
            sort_dir: ``"D"`` 降序 / ``"A"`` 升序。
            sort_begin/sort_count: 排序分页窗口（服务端默认返回
                ``sortcount=26``）。

        Returns:
            list[dict]，按排序序，每条含 ``code`` + ``value``（排序字段值，
            语义随 sort_by：涨跌幅/涨速为百分比，主力为元，涨停/涨跌家为
            个数）+ ``dt<SortBy>`` 原始键。
        """
        return self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._board_service.hot_boards_sorted(
                sort_by,
                codes=codes,
                sort_dir=sort_dir,
                sort_begin=sort_begin,
                sort_count=sort_count,
                timeout=timeout,
            ),
        )

    def board_quotes(
        self,
        codes: list[str] | None = None,
        *,
        timeout: float = 40.0,
    ) -> list[dict]:
        """板块指数行情列表。

        板块代码统一挂 market=48（行业 881xxx / 概念 885xxx 等）。首次调用
        自动建立**板块专用通道**（fu4.123ths.com 独立 8901 连接 + 完整引导
        序列），后续查询复用。在 MAIN 连接上重放相同请求只会得到
        CodeListSize=0（服务器按连接身份路由，见 docs/plans/FEATURE_GAP_ROADMAP.md）。

        Args:
            codes: 板块指数代码列表，如 ``["881101", "885480"]``；传 ``None``
                表示发送全量请求（抓包确认的 513 个板块指数一次拉取，
                DataType=527527，响应为 0x20/0x1c/0x22 紧凑表）。
            timeout: 两条成分连接建连与查询的总超时（秒）。

        Returns:
            list[dict]，每条含 ``code``/``name``/``dt10``（最新价）/
            ``dt6``/``dt48``（涨幅）等字段。

        Raises:
            RuntimeError: 未登录或板块通道建连失败。
        """
        return self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._board_service.board_quotes(
                codes,
                timeout=timeout,
            ),
        )

    def board_timeline(
        self,
        code: str,
        date=None,
        *,
        timeout: float = 12.0,
    ) -> list[dict]:
        """板块指数当日/历史分时（0x42 表，242 点/日）。

        Args:
            code: 板块指数代码（如 ``"881121"`` 半导体）。
            date: ``None``=当日；``"YYYY-MM-DD"``/``date``=历史日（packed-date
                游标编码）。
            timeout: 单帧读取超时（秒）。

        Returns:
            list[dict]，每条含 ``date``/``minute_index``/``dt10``/``dt13``/
            ``dt19`` 等字段。
        """
        return self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._board_service.board_timeline(
                code,
                date=date,
                timeout=timeout,
            ),
        )

    def board_kline(
        self,
        code: str,
        *,
        fuquan: str = "Q",
        count: int = 2146,
        anchor: int = 0,
        timeout: float = 12.0,
    ) -> list[dict]:
        """板块指数日K（period=16384，0x42 日K 表）。

        Args:
            code: 板块指数代码（如 ``"881121"`` 半导体）。
            fuquan: 复权（``Q`` 前复权 / ``H`` 后复权 / ``""`` 不复权）。
            count: 请求根数（服务端返回 count+1 根，受板块发布日截断）。
            anchor: 0=最新；翻页时设为上一窗口最早一根的 YYYYMMDD。
            timeout: 单帧读取超时（秒）。

        Returns:
            list[dict]，每条含 ``time``（datetime）/``open``/``high``/
            ``low``/``close``/``volume``/``amount``。
        """
        return self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._board_service.board_kline(
                code,
                fuquan=fuquan,
                count=count,
                anchor=anchor,
                timeout=timeout,
            ),
        )

    def board_auction(
        self,
        code: str,
        date=None,
        *,
        timeout: float = 12.0,
    ) -> list[dict]:
        """板块指数集合竞价（0x32 表：unix 秒 + 撮合价 + 累计量）。

        Args:
            code: 板块指数代码。
            date: ``None``=当日；``"YYYY-MM-DD"``/``date``=历史日。
            timeout: 单帧读取超时（秒）。

        Returns:
            list[dict]，每条含 ``time``/``dt10``/``dt49`` 等字段。
        """
        return self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._board_service.board_auction(
                code,
                date=date,
                timeout=timeout,
            ),
        )

    def board_constituents(
        self,
        codes: list[str],
        *,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块成分股行情（L2 0x64；普通账号 0x44/0x50 表）。

        0x64 请求本身接收的是**成分股代码列表**，不具备“板块代码服务端展开”
        语义（真实客户端同样由本地 BlockUpdate 展开后再发请求，94 页面
        成分股组件只是路由不同，见 HANDOFF_HOT_BOARD_12480_20260807.md）。
        门面先把稳定板块 ID 展开为股票代码，再走 fu4 批量取行情。成分股
        连接独立于板块指数连接：普通/沪侧使用标准身份，Level2 深侧使用
        manual 身份。

        板块指数代码的展开路径（2026-09-09 实测 513/513 全覆盖）：

        1. 直接命中本地稳定 ID（881xxx 行业板块同号同名）；
        2. 概念/二级行业指数（882/885/886xxx）在本地 BlockUpdate 里是
           十六进制 block_id（如 C5FE=培育钻石），走**名称桥接**：
           name_48 名称组缓存给出指数代码的名称 → 精确匹配本地 A 股
           类别（行业/概念/地域）板块名 → 取其 block_id 展开。

        Args:
            codes: 稳定板块 ID 或板块指数代码列表（如 ``["881121"]``、
                ``["885937"]``）。

        Returns:
            list[dict]，每条含 ``code``（6 位股票代码）及 ``dt<N>`` 字段；
            全部无法展开时返回空列表。
        """
        from ..services.system_blocks import SystemBlocksError

        stock_codes: list[str] = []
        stock_markets: dict[str, int | str] = {}
        seen: set[str] = set()

        def take(block_id: str) -> None:
            for stock in self.system_blocks.constituents(block_id):
                if not stock.pattern and stock.code not in seen:
                    seen.add(stock.code)
                    stock_codes.append(stock.code)
                    stock_markets[stock.code] = stock.market

        unresolved: list[str] = []
        for block_id in codes:
            key = str(block_id)
            try:
                take(key)
            except SystemBlocksError:
                unresolved.append(key)
        for key, block_id in self._bridge_board_names(unresolved).items():
            take(block_id)
        if not stock_codes:
            # 未知板块/名称组缺失：返回空列表，前端显示“暂无数据”，
            # 不抛 400/500（bridge 失败通常是当日名称组尚未拉取）。
            return []
        records = self._run_default_service(
            (
                Capability.BASIC_QUOTE,
                Capability.L2_MARKET_ACCESS,
            ),
            lambda: self._board_service.board_constituents(
                stock_codes,
                stock_markets=stock_markets,
                timeout=timeout,
            ),
        )
        # 通道的 dt66 涨幅收盘后为 0/盘中滞后（2026-09-09 实测），但 dt10/dt6
        # 现价昨收可靠：本地补算 chg_pct，前端列表到达即完整可排序，
        # 不必再等 quotes_ext 二跳（对齐真实客户端“一次肥查询带全列”）。
        for row in records:
            prev = row.get("dt6")
            price = row.get("dt10")
            if prev and price:
                row["chg_pct"] = (price / prev - 1) * 100
        return records

    # 桥接仅限 A 股类别：美股/港股/ETF 等本地同名板块（如“港口航运[US]”）
    # 名称带后缀不会误撞；同名的跨类别板块以先见者为准（categories()
    # 中 industry 排最前，行业优先）。
    _BRIDGE_BLOCK_CATEGORIES = frozenset(
        {"industry", "concept", "region"}
    )

    def _bridge_board_names(self, board_codes: list[str]) -> dict[str, str]:
        """板块指数代码 → 本地稳定 block_id（name_48 名称精确匹配）。

        name_48 名称组当日有效（磁盘缓存，命中后无网络请求）；本地
        板块名表与逐代码解析结果按自然日在进程内累积缓存，多次单代码
        调用（Web 端点形态）复用同一天的桥接表。名称取不到或本地无
        同名板块的代码不进入返回值，由调用方决定后续行为。
        """
        board_codes = [str(code) for code in board_codes if code]
        if not board_codes:
            return {}
        today = date_type.today()
        if getattr(self, "_board_name_bridge_day", None) != today:
            self._board_name_bridge_day = today
            self._board_name_bridge: dict[str, str] = {}
            self._board_name_bridge_local: tuple[
                dict[str, str], dict[str, str]
            ] | None = None
        bridge = self._board_name_bridge
        pending = [code for code in board_codes if code not in bridge]
        if not pending:
            return {code: bridge[code] for code in board_codes if code in bridge}
        if self._board_name_bridge_local is None:
            try:
                names = self.fetch_stock_names_full()["names"]
            except Exception as exc:
                logger.warning(
                    "board_constituents: 板块名称桥接失败: %s", exc
                )
                return {}
            local_names: dict[str, str] = {}
            for block in self.system_blocks.boards():
                if (
                    block.category in self._BRIDGE_BLOCK_CATEGORIES
                    and block.name not in local_names
                ):
                    local_names[block.name] = block.block_id
            self._board_name_bridge_local = (names, local_names)
        names, local_names = self._board_name_bridge_local
        for code in pending:
            if names.get(code, "") in local_names:
                bridge[code] = local_names[names[code]]
        logger.info(
            "board_constituents: 名称桥接新增 %d、累计 %d 个板块指数",
            len(pending),
            len(bridge),
        )
        return {code: bridge[code] for code in board_codes if code in bridge}

    # ── 板块统计计算（9601 statscalc / calcext，独立于 fu4 8901 板块通道）──

    def board_stats_interval(
        self,
        codes: list[str],
        *,
        market: int = 48,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块区间涨跌幅/涨速聚合统计（9601 statscalc，hd1.0 表）。

        服务端计算型协议（``dataclass=intervalcalc datatype=330342``），与
        :meth:`board_quotes`（8901 fu4 预存字段）互补；两者可交叉验证。走独立
        统计节点（``8.132.233.77:9601``，不在 DNS/passport）。

        Args:
            codes: 板块指数代码列表（如 ``["881121", "885897"]``）。
            market: 板块市场（默认 48）。
            timeout: 单次请求超时（秒）。

        Returns:
            list[dict]，每条含 ``code``（前导零补齐，如 ``"0881121"``）/
            ``date``（形如 20160127）/``value``（涨跌幅%，浮点）。统计节点不可达
            或超时时返回空列表（可降级 :meth:`board_quotes`）。
        """
        return self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._board_stats_service.statscalc_interval(
                codes,
                market=market,
                timeout=timeout,
            ),
        )

    def board_stats_updownlimit(
        self,
        codes: list[str],
        *,
        market: int = 48,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块涨跌停统计（9601 statscalc，dataclass=updownlimit）。

        Args/Returns 同 :meth:`board_stats_interval`，``value`` 为涨跌停家数统计。
        """
        return self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._board_stats_service.statscalc_updownlimit(
                codes,
                market=market,
                timeout=timeout,
            ),
        )

    def board_calcext(
        self,
        code: str,
        market: int,
        *,
        datatype: str = "199359",
        timeout: float = 15.0,
    ) -> list[dict]:
        """单股/单板块扩展计算（9601 calcext，rettype=json）。

        走 REALORDER 节点（与 ``qurealorder`` 共享 9601 socket）。常用于取流通
        市值（``datatype=199359``）等单点扩展字段。

        Args:
            code: 单个证券代码（如 ``"600030"`` / ``"881121"``）。
            market: 代码所属市场（17=沪 / 33=深 / 48=板块）。
            datatype: 计算字段编号，默认 ``199359``（流通市值）。
            timeout: 单次请求超时（秒）。

        Returns:
            list[dict]，每条含 ``market``/``code``/``value``（数值，类型取决于
            datatype）。REALORDER 通道不可达时返回空列表。
        """
        # calcext 与 qurealorder 共享 REALORDER 9601 socket，门控与短线精灵一致
        # （REALORDER 能力证据在首次 9601 建连时懒建立）。
        return self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._board_stats_service.calcext(
                code,
                market,
                datatype=datatype,
                timeout=timeout,
            ),
        )
