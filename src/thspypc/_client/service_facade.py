"""Public market-data facade methods backed by services."""
from __future__ import annotations

import logging
import os
from datetime import date as date_type, datetime

from ..errors import ChannelUnavailableError, ProtocolError
from ..models import AccountKind, Capability, DepthQuote
from ..protocol import LIST_QUOTE_DATATYPE_DEFAULT, pick_l2_market
from ..transport import ConnectionRole
from .stock_cache import (
    default_stock_cache_path,
    load_stock_codes,
    market_from_code,
    save_stock_codes,
)

logger = logging.getLogger(__name__)


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
        if not refresh:
            loaded = load_stock_codes(path)
            if loaded is not None:
                stocks, saved_date = loaded
                logger.info("stock_list_cached: 命中缓存 (%s, %d 条)",
                            saved_date, len(stocks))
                return stocks
        # 缓存不存在/过期/强制刷新 → 走网络
        logger.info("stock_list_cached: 缓存未命中，走 stock_list() 拉取...")
        stocks = self.stock_list(timeout=timeout, with_names=with_names)
        # 覆盖 market 字段为派生值（stock_list 返回的 market 恒为 0）
        for s in stocks:
            s["market"] = market_from_code(s["code"])
        # 仅在拿到有效结果时写盘，避免失败的拉取被缓存一整天
        if stocks:
            save_stock_codes(stocks, path)
        else:
            logger.warning("stock_list_cached: 拉取为空，不写缓存（可重试）")
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

        ⚠ **默认名称源是** :meth:`load_hexin_names`（同花顺本地缓存，瞬时、稳定、
        覆盖沪深北 A 股）。本方法仅作探索性补充——且对主用途（A 股名称）无增益：
        thspypc 拿到的增量帧恰好是未解的 ``name_16_16`` 块状段。

        发送 ``method=upstockname`` 请求，解析响应中的 ``[name_<MARKET>]`` 段。
        纯文本段（外汇/期货/北交所/外盘等）直接解出；块状自定义编码段
        （沪深 A 股 ``name_16_16``）当前跳过（编码未逆向，简单模型已穷举证伪，见
        :func:`thspypc.protocol.decode_name_frame` 与
        docs/handoffs/HANDOFF.md §6a/§6b）。

        服务器按账号追踪名称版本，thspypc 账号通常只能拿到**增量**（~12 条），
        全量需 hexin 客户端冷启动触发。本方法适合补充 :meth:`load_hexin_names`
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

    @staticmethod
    def load_hexin_names(
        stockname_dir: str | None = None,
    ) -> dict[str, str]:
        """从同花顺本地缓存加载股票代码→名称映射（**默认名称源**）。

        这是获取 A 股名称的推荐方式——瞬时、稳定、零网络依赖，覆盖沪深北交易所。
        相比网络协议 :meth:`fetch_stock_names`（块状段未解、只能拿增量），本方法
        是主用途的首选。

        读取 ``<hexin_dir>/stockname/stockname_*_0.txt`` 文件，
        解析 ``CODE=NAME|ALIAS@FLAG`` 格式。仅保留 6 位数字代码。

        Args:
            stockname_dir: stockname 目录路径。为 None 时自动探测常见安装位置：
                ``C:/同花顺软件/同花顺/stockname/``。

        Returns:
            dict[str, str]，键为 6 位数字代码（如 "600000"），值为中文名称（如 "浦发银行"）。
            约 8000+ 条（覆盖沪深北交易所）。
        """
        if stockname_dir is None:
            # 自动探测常见安装路径
            candidates = [
                r"C:\同花顺软件\同花顺\stockname",
                r"D:\同花顺软件\同花顺\stockname",
                os.path.expandvars(r"%LOCALAPPDATA%\同花顺\stockname"),
                os.path.expandvars(r"%APPDATA%\同花顺\stockname"),
            ]
            for c in candidates:
                if os.path.isdir(c):
                    stockname_dir = c
                    break
        if not stockname_dir or not os.path.isdir(stockname_dir):
            logger.warning("load_hexin_names: stockname 目录不存在，返回空映射。"
                           "请安装同花顺 PC 客户端或手动指定 --stockname-dir")
            return {}

        names: dict[str, str] = {}
        for fname in sorted(os.listdir(stockname_dir)):
            # 只读 _0.txt 基础文件（_1.txt 是增量，.base 是备份）
            if not (fname.endswith("_0.txt") and fname.startswith("stockname_")):
                continue
            fpath = os.path.join(stockname_dir, fname)
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
            except OSError:
                continue
            try:
                text = raw.decode("gbk", errors="replace")
            except UnicodeDecodeError:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("[") or line.startswith("ConfigVer"):
                    continue
                if "=" not in line:
                    continue
                code, _, rest = line.partition("=")
                # 只取 6 位纯数字代码（A 股/北交所/新三板）
                if not (code.isdigit() and len(code) == 6):
                    continue
                name = rest.split("|")[0].split("@")[0].strip()
                if name:
                    names[code] = name

        logger.info("load_hexin_names: 从 %s 加载 %d 条名称",
                    stockname_dir, len(names))
        return names

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
    ) -> list[dict]:
        """查 K线（复用登录后的 8901 长连接，复刻 hexin 单连接连发模式）。

        发送 ``build_kline_query`` 构造的 K线请求，解析 ``parse_kline_hd3_response``
        返回的 hd3.1 变体响应（flag=0x0042/0x0046），返回 OHLCV 记录列表。

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
        kline_capability = (
            Capability.BASIC_QUOTE
            if profile.kind is AccountKind.STANDARD
            else Capability.L2_TIMELINE
        )

        last_err = ""
        for attempt in range(retries + 1):
            # ensure_connected 对从未登录会 raise；这里统一用 is_connected 判断，
            # 连接不在则 connect()（首次登录 + 断线重连都走这里，IP 轮换取新连接）
            if not self.is_connected:
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
        skip_init: bool = False,
        use_main_ip: bool = False,
        prev_close: float | None = None,
    ) -> list[dict]:
        """查当日分时图（含指数白线及领先线）。

        普通账号走 MAIN 上的 ``pageid=9354`` 请求-响应；Level2 账号走
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
        from ..errors import ChannelUnavailableError

        if skip_init or use_main_ip:
            raise ValueError(
                "skip_init/use_main_ip 仅用于已移除的 legacy 诊断路径"
            )
        if market == 0:
            market = self._market_for_code(code)
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
        if (
            capability is Capability.L2_TIMELINE
            and self._snapshot_thread is not None
            and self._snapshot_thread.is_alive()
        ):
            raise ChannelUnavailableError(
                "l2_snapshot",
                "后台快照线程正在读取 4214 连接",
            )
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
        skip_init: bool = False,
        use_main_ip: bool = False,
    ) -> list[dict]:
        """查集合竞价（9:15-9:25 每 9 秒一次虚拟撮合：撮合价/累计量/未匹配量）。

        普通账号走 MAIN：当天请求用 ``pageid=9354/period=7176``，历史交易日
        用 ``pageid=9355/period=6144``。Level2 账号保留 4214 通道路径。

        Args:
            code: 股票或指数代码（如 ``"000938"``、``"1A0001"``）。
            market: 市场码（0=按代码前缀自动推断：6xx=沪17，其余=深33）。
            trade_date: 交易日。``None``（默认）= 最近交易日；传 ``date``/``datetime``
                = 指定交易日（算该日 9:15/9:25 unix 时间戳）。沪深竞价时段相同。
                ★ 历史日期的 DateTime 格式基于当日抓包推断，若实测不符需调整。
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
        from ..errors import ChannelUnavailableError

        if skip_init or use_main_ip:
            raise ValueError(
                "skip_init/use_main_ip 仅用于已移除的 legacy 诊断路径"
            )
        if market == 0:
            market = self._market_for_code(code)
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
        if (
            capability is Capability.L2_AUCTION
            and self._snapshot_thread is not None
            and self._snapshot_thread.is_alive()
        ):
            raise ChannelUnavailableError(
                "l2_snapshot",
                "后台快照线程正在读取 4214 连接",
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
            ChannelUnavailableError: 后台快照线程正在占用 4214 连接。

        Note:
            ``delegate_a``(dt12)/``delegate_b``(dt74) 的买卖语义沪深不同：深市
            a=卖方/b=买方，沪市 a=主动方/b=被动方挂单。详见
            ``superorder_protocol`` 模块 docstring。
        """
        from ..errors import ChannelUnavailableError

        if market == 0:
            market = self._market_for_code(code)
        start_ts = self._superorder_ts(start)
        end_ts = self._superorder_ts(end)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        profile = (
            self._service_connections.profile
            if self._service_connections is not None
            else self.observed_account_profile
        )
        if (
            profile.kind is AccountKind.LEVEL2
            and self._snapshot_thread is not None
            and self._snapshot_thread.is_alive()
        ):
            raise ChannelUnavailableError(
                "l2_snapshot",
                "后台快照线程正在读取 4214 连接",
            )

        # L2 逐笔回放单次请求（与 timeline/depth_ten 一致；连接治理交给
        # ConnectionManager，它在 acquire 时自动重建失效连接）。
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
        timeout: float = 30.0,
    ) -> list[dict]:
        """查盘口快照回放（period=4096，超级盘口分时曲线）。

        返回全天每 ~3 秒一个完整盘口快照（~4927 点），每条含十档买卖价量。
        **仅 Level2 账号可用**。走对应市场的 Level2 连接（pageid=4260）。

        Args:
            code: 股票代码（如 ``"000938"``、``"603118"``）。
            market: 市场码（0=按代码前缀自动推断）。
            timeout: 单次 read_frame 超时（秒）。全天数据 ~500KB，默认 30s。

        Returns:
            盘口快照记录列表，每条 ``{time, ts, price, dt24-35(五档),
            dt102-125(六~十档), ...}``，按时间正序。

        Raises:
            CapabilityUnavailableError: 普通账号无 L2 通道。
            ChannelUnavailableError: 后台快照线程正在占用 4214 连接。
        """
        from ..errors import ChannelUnavailableError

        if market == 0:
            market = self._market_for_code(code)
        if self._auth is None and self._service_connections is None:
            self.authenticate()
        profile = (
            self._service_connections.profile
            if self._service_connections is not None
            else self.observed_account_profile
        )
        if (
            profile.kind is AccountKind.LEVEL2
            and self._snapshot_thread is not None
            and self._snapshot_thread.is_alive()
        ):
            raise ChannelUnavailableError(
                "l2_snapshot",
                "后台快照线程正在读取 4214 连接",
            )

        return self._run_default_service(
            (Capability.L2_TIMELINE,),
            lambda: self._superorder_service.snapshot_replay(
                code,
                market=market,
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
        if (
            capability is Capability.L2_AUCTION
            and self._snapshot_thread is not None
            and self._snapshot_thread.is_alive()
        ):
            raise ChannelUnavailableError(
                "l2_snapshot",
                "后台快照线程正在读取 4214 连接",
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
        value = trade_date
        if isinstance(value, str):
            value = date_type.fromisoformat(value)
        elif isinstance(value, datetime):
            value = value.date()
        historical = value is not None and value != date_type.today()

        historical_index = historical and market in (16, 32, 144)
        opening = (
            []
            if historical_index
            else self.auction(
                code,
                market=market,
                trade_date=trade_date,
                timeout=timeout,
            )
        )
        if historical:
            continuous = self.history_timeline(
                code,
                value,
                market=market,
                timeout=timeout,
                retries=retries,
            )
        else:
            continuous = self.timeline(
                code,
                market=market,
                timeout=timeout,
            )
        closing = (
            []
            if historical_index
            else self.closing_auction(
                code,
                market=market,
                trade_date=trade_date,
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
        from ..errors import ChannelUnavailableError

        if (
            self._snapshot_thread is not None
            and self._snapshot_thread.is_alive()
            and (
                (
                    self._service_connections.profile
                    if self._service_connections is not None
                    else self.observed_account_profile
                ).kind
                is AccountKind.LEVEL2
            )
        ):
            raise ChannelUnavailableError(
                "l2_snapshot",
                "后台快照线程正在读取 L2 连接",
            )

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

    def stock_list_hot(
        self,
        count: int = 29,
        timeout: float = 10.0,
        with_names: bool | str = False,
        sort_by: int = 199112,
        sort_dir: str = "D",
        max_pages: int = 120,
    ) -> list[dict]:
        """获取排序榜单（自动翻页，可拿完整榜单）。

        发送排序代码表查询（同花顺打开 A 股列表、切换排序列时发的请求），
        服务器按 ``sort_by`` 指定的字段排序后返回。本方法自动用 SortBegin 游标
        翻页，直到拿满 ``count`` 条或取完整个榜单。

        ``sort_by`` 是排序键编号（见 :data:`protocol.SORT_BY_VALUES`，均为活网验证）：
        涨幅=199112、涨速=48、换手率=1968584、量比=1771976、主力净流入=592890、
        竞价金额=68758、竞价涨幅=68762。默认按涨幅降序（涨幅榜）。
        换成跌幅榜传 ``sort_by=199112, sort_dir="A"``（升序值 A 为推测，未实测）。

        ⚠ 成交量/成交额**不能**通过本方法拿——它们不走 SortBy 路径，而是客户端
        订阅行情推送（dt13/dt19）后本地排序。详见
        docs/handoffs/HANDOFF_STOCKLIST_PUSH.md。

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

        Returns:
            list[dict]，每项 ``{"code": "600519", "name": "贵州茅台"}``。
            按 code 去重（页边界可能重叠）。

        Raises:
            RuntimeError: 未登录。
        """
        self._ensure_main_connection()
        stocks = self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._stock_list_service.ranked(
                count=count,
                timeout=timeout,
                sort_by=sort_by,
                sort_dir=sort_dir,
                max_pages=max_pages,
            ),
        )
        if with_names and stocks:
            stockname_dir = (
                with_names if isinstance(with_names, str) else None
            )
            name_map = self.load_hexin_names(stockname_dir)
            for stock in stocks:
                name = name_map.get(stock["code"], "")
                if name:
                    stock["name"] = name
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
                - True: 自动从同花顺本地缓存加载名称（需安装同花顺 PC 客户端）
                - str: 指定 stockname 目录路径

        Returns:
            list[dict]，每项 ``{"code": "600000", "name": "浦发银行"}``。
            约 7400 条，按 dt5 代码字段顺序（通常代码升序）。
            with_names=False 时 name 恒为 ""。

        Raises:
            RuntimeError: 未登录。
        """
        self._ensure_main_connection()
        stocks = self._run_default_service(
            (Capability.BASIC_QUOTE,),
            lambda: self._stock_list_service.full_list(timeout=timeout),
        )
        if with_names and stocks:
            stockname_dir = (
                with_names if isinstance(with_names, str) else None
            )
            name_map = self.load_hexin_names(stockname_dir)
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
        """全市场行情快照：一个请求拿沪市全市场 code+name（~0.13s）。

        在 :meth:`connect` 建立的**主连接**上发 hfd1.0 空括号请求
        （``CodeList=16();17();...``），服务器一次性返回整个市场的股票代码和
        名称。相比 :meth:`list_quotes` 逐批查询（~250 请求），本方法只需 1 个请求，
        速度提升 2~3 个数量级。

        ⚠️ **数值字段（price/change_pct 等）当前为近似值**，通过 THS float 扫描
        推断，准确度有限。对于准确行情请用 :meth:`list_quotes`（或
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
            list[dict]，每项 ``{"code", "name", "price", "change_pct", ...}``，
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

        ⚠️ 需要 **level2 账号**：普通账号打开分时走 pageid=9354（请求-响应，无推送）。
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
        if market is None:
            market = 17 if code.startswith("6") else 33

        from ..errors import ProtocolError
        from ..protocol import pick_l2_market

        key = pick_l2_market(market)
        if self._auth is None and self._service_connections is None:
            self.authenticate()

        def register() -> bool:
            role = (
                ConnectionRole.SH_L2
                if key == "sh"
                else ConnectionRole.SZ_L2
            )
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

        try:
            self._run_default_service(
                (Capability.L2_SNAPSHOT_PUSH,),
                register,
            )
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

    def latest_price(self, code: str) -> float | None:
        """取某代码的最新现价（snapshot_subscribe 后由推送线程更新）。"""
        return self._latest_price.get(code)

    def latest_depth(self, code: str) -> dict | None:
        """取某代码的最新十档盘口（549B 推送解析结果）。

        返回 ``parse_depth_push`` 的 dict（含 price/prev_close/open/high/low/
        bids[10]/asks[10]），或 None。需先 ``snapshot_subscribe`` 且盘中
        服务器推送了 549B 十档帧。
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

    def dxjl_latest(self, markets: tuple = (32, 16)) -> list[dict]:
        """获取短线精灵最新一页（沪深）。

        Args:
            markets: 市场元组，默认 (32, 16) = 深沪。

        Returns:
            list[dict]，按时间倒序（最新在前）。非交易时段可能为空。
        """
        return self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._realorder_service.dxjl_latest(markets=markets),
        )

    def dxjl_history(self, pages: int = 5, markets: tuple = (32, 16)) -> list[dict]:
        """翻页获取短线精灵历史数据（endtime 游标分页）。

        翻页机制：第 N+1 页的 endtime = 第 N 页最早记录的时间戳。

        Args:
            pages: 翻页数。
            markets: 市场元组，默认 (32, 16) = 深沪。

        Returns:
            list[dict]，按时间倒序。
        """
        return self._run_default_service(
            (Capability.REALORDER,),
            lambda: self._realorder_service.dxjl_history(
                pages=pages,
                markets=markets,
            ),
        )

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
        语义。门面先用本机系统板块缓存把稳定板块 ID 展开为股票代码，再走 fu4
        批量取行情。成分股连接独立于板块指数连接：普通/沪侧使用标准身份，
        Level2 深侧使用 manual 身份。

        Args:
            codes: 稳定板块 ID 列表（如 ``["881121"]``）。
            timeout: 单帧读取超时（秒）。

        Returns:
            list[dict]，每条含 ``code``（6 位股票代码）及 ``dt<N>`` 字段。
        """
        stock_codes: list[str] = []
        stock_markets: dict[str, int | str] = {}
        seen: set[str] = set()
        for block_id in codes:
            for stock in self.system_blocks.constituents(block_id):
                if not stock.pattern and stock.code not in seen:
                    seen.add(stock.code)
                    stock_codes.append(stock.code)
                    stock_markets[stock.code] = stock.market
        return self._run_default_service(
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
