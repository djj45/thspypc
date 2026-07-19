"""
同花顺 PC 远航版行情客户端。

登录打通 + 个股列表行情查询 + 自定义板块管理 + 短线精灵（异动）查询。
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field

from . import protocol
from .protocol import (
    LIST_QUOTE_DATATYPE_DEFAULT,
    MARKET_HOSTS,
    MARKET_PORT,
    REALORDER_HOST,
    REALORDER_PORT,
    STOCK_LIST_DATATYPE,
    SUBREAL_CHANNELS,
    build_heartbeat_8901,
    build_heartbeat_9601,
    build_init_query,
    build_list_quote_query,
    build_login_body_pc,
    build_passport64,
    build_qurealorder_query,
    build_stock_list_query,
    build_subreal_query,
    encode_frame,
    full_http_auth,
    generate_imei,
    generate_mac64,
    parse_hd1_response,
    parse_hd3_response,
    parse_init_response,
    parse_login_response,
    parse_passport_fields,
    parse_qurealorder_response,
    parse_pushrealorder_response,
    parse_stock_list_response,
    read_frame,
    read_frame_realorder,
)

logger = logging.getLogger(__name__)


@dataclass
class LoginResult:
    """登录结果，含诊断信息。"""
    success: bool                          # VerifyCode == "0"
    verify_code: str = ""                  # 服务器返回的 VerifyCode
    server: str = ""                       # 实际连上的 8901 服务器 IP
    reply_fields: dict = field(default_factory=dict)   # 完整响应字段
    passport_fields: dict = field(default_factory=dict)  # passport 里的权限字段（诊断用）
    error: str = ""                        # 失败原因分类标签
    detail: str = ""                       # 失败详情（异常信息等）


class THSClient:
    """同花顺 PC 远航版行情客户端。

    Args:
        username: 同花顺账号
        password: 密码
        imei: 设备 ID（32 字符十六进制，hexin.exe 本地生成的硬件指纹）。
              算法已逆向（见 protocol.generate_imei）：MD5(MAC大写连字符 + "0"*30)。
              None 时自动生成（脱离抓包运行）。
        mac64: login 帧的 Mac64 字段值。None 时自动生成（base64(0x18 + 前4网卡MAC)，
               已逆向验证，与 hexin.exe 一致）。

    Mac64 与 imei 都已逆向，均可自动生成，thspypc 完全脱离抓包运行。
    """

    def __init__(self, username: str, password: str, imei: str | None = None, mac64: str | None = None,
                 enable_heartbeat: bool = True):
        self.username = username
        self.password = password
        self.imei = imei if imei is not None else generate_imei()
        self.mac64 = mac64 if mac64 is not None else generate_mac64()
        self.enable_heartbeat = enable_heartbeat
        self._sock: socket.socket | None = None
        self._auth: dict | None = None
        # 板块/自选股管理（HTTPS，登录后初始化）
        self._blocks = None              # BlockManager 实例
        self._http_cookies: dict | None = None
        # 短线精灵（9601 TCP，懒连接）
        self._realorder_sock: socket.socket | None = None
        self._instance = 700000          # 请求序列号
        # 心跳（后台线程，connect 成功后自动启动）
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_stop = threading.Event()
        self._sock_lock = threading.Lock()              # 保护 8901 socket send
        self._realorder_lock = threading.Lock()         # 保护 9601 socket send
        self._hb_seq_8901 = 0
        self._hb_seq_9601 = 0

    def connect(self) -> LoginResult:
        """账号密码登录：HTTP 鉴权 → 构造 PC login 帧 → 连 8901 → 验证。

        返回 LoginResult，含成功/失败诊断。失败时 error 字段区分：
          - "http_auth_failed"   HTTP 三步鉴权失败（账号/密码/网络问题）
          - "all_hosts_failed"   所有 8901 IP 都连不上（网络/防火墙）
          - "login_rejected"     连上了但 VerifyCode != 0（passport 被拒）

        VerifyCode=-1 不是账号级限流（实测同账号连不同 IP，第2次 -1 但第3次
        又成功）。hexin 客户端连 7 个 IP 并发所以不受影响。本方法遇到 -1 会
        自动换下一个 host 重试（不冷却等待）。
        """
        # ---- 第 1 步：HTTP 三步鉴权 ----
        try:
            logger.info("开始 HTTP 三步鉴权 (account=%s)...", self.username)
            self._auth = full_http_auth(self.username, self.password, self.imei)
            passport_fields = parse_passport_fields(self._auth["passport_bytes"])
            logger.info("HTTP 鉴权成功，passport 含 %d 个字段", len(passport_fields))
            logger.debug("passport 关键字段: account=%s, userclass=%s, level2=%s",
                         passport_fields.get("account", "?"),
                         passport_fields.get("userclass", "?"),
                         passport_fields.get("level2", "?"))
        except Exception as e:
            logger.error("HTTP 鉴权失败: %s", e)
            return LoginResult(success=False, error="http_auth_failed", detail=str(e))

        # 板块/自选股功能初始化（HTTP 鉴权后、TCP 登录前；失败不影响登录）
        self._init_blocks()

        return self._do_tcp_login(passport_fields)

    def _init_blocks(self) -> None:
        """初始化板块/自选股管理（HTTPS cookie 鉴权）。

        从 self._auth 提取 userid/sessionid/signvalid → docookie2 拿 cookies →
        BlockManager。失败仅 warning，不影响 TCP 登录和行情查询。
        前置条件：self._auth 已通过 full_http_auth 设置。
        """
        if self._auth is None:
            return
        try:
            passport_bytes = self._auth.get("passport_bytes", b"")
            if isinstance(passport_bytes, str):
                passport_bytes = passport_bytes.encode()
            signvalid = ""
            for f in passport_bytes.split(b"|"):
                if f.startswith(b"signvalid="):
                    signvalid = f[len(b"signvalid="):].decode("ascii", errors="replace")
                    break
            from .blocks import BlockAuth, BlockManager
            auth = BlockAuth()
            self._http_cookies = auth.docookie2(
                self._auth.get("userid", ""),
                self._auth.get("sessionid", ""),
                signvalid,
            )
            self._blocks = BlockManager(cookies=self._http_cookies)
            logger.info("板块/自选股功能已就绪")
        except Exception as e:
            logger.warning("板块功能初始化失败（不影响登录）: %s", e)

    def connect_with_qrcode(self, timeout: float = 180.0, png_path: str | None = None,
                            cache_path: str | None = None) -> LoginResult:
        """二维码扫码登录：生成二维码 → 等待手机扫码 → HTTP 鉴权 → 8901。

        扫码成功后用返回的 account/password 走 full_http_auth 拿 passport，
        后续 TCP login 与 connect() 相同。

        Args:
            timeout: 等待扫码确认的最长秒数（二维码默认有效期 ~120s）
            png_path: 若给定，把二维码 PNG 存到该路径（终端 ASCII 扫不了时用图片扫）
            cache_path: 若给定（默认 ~/.ths_qr_credentials.json），扫码成功后把凭证
                        存盘，供 connect_cached() 免扫码复用。传 "" 可禁用缓存。

        error 字段额外值：
          - "qr_timeout"   扫码超时未确认
          - "qr_failed"    二维码生成/轮询失败
        """
        from .qr_login import qr_login_flow, save_credentials, QrLoginResult
        # ---- 第 1 步：二维码扫码拿账号 ----
        try:
            qr: QrLoginResult = qr_login_flow(timeout=timeout, show_qr=True, png_path=png_path)
            logger.info("扫码登录拿到账号: %s", qr.account)
        except TimeoutError as e:
            return LoginResult(success=False, error="qr_timeout", detail=str(e))
        except Exception as e:
            logger.error("二维码登录失败: %s", e)
            return LoginResult(success=False, error="qr_failed", detail=str(e))

        # ---- 第 1.5 步：缓存扫码凭证（供下次免扫码）----
        if cache_path != "":
            try:
                saved = save_credentials(qr, cache_path or None)
                logger.info("扫码凭证已缓存到 %s", saved)
            except Exception as e:
                logger.warning("凭证缓存失败（不影响登录）: %s", e)

        return self._http_auth_and_tcp_login(qr.account, qr.password)

    def connect_cached(self, cache_path: str | None = None,
                       qr_timeout: float = 180.0,
                       png_path: str | None = None) -> LoginResult:
        """带凭证缓存的登录：优先用缓存凭证，过期才回退到扫码。

        手机勾选「30天免登录」后，凭证有效期 30 天，期间无需再扫码。
        缓存路径默认 ~/.ths_qr_credentials.json。

        流程：
          1. 读缓存凭证 → 仍有效 → 直接 HTTP 鉴权 + 8901（秒登录）
          2. 缓存过期/不存在 → 回退到 connect_with_qrcode（扫码 + 重新缓存）

        Args:
            cache_path: 凭证缓存路径，None 用默认路径
            qr_timeout: 回退扫码时的等待超时
            png_path: 回退扫码时的 PNG 备用路径

        自适应策略：不靠时间预判凭证有效性，而是「先试再说」——
          1. 有缓存且未「确定过期」→ 直接用缓存凭证试登录，成功就秒登
          2. 缓存登录失败 / 确定过期 → 清缓存，回退扫码（重新缓存）
        这样无论服务器实际让凭证活多久，都能自动适应，无需关心是否勾选了 30 天。
        """
        from .qr_login import load_credentials, is_credentials_expired

        # ---- 1. 有缓存且未「确定过期」→ 先试一次 ----
        loaded = load_credentials(cache_path)
        if loaded is not None:
            result_cred, saved_at = loaded
            if not is_credentials_expired(result_cred, saved_at):
                logger.info("尝试缓存凭证（account=%s, expire_time=%s）",
                            result_cred.account,
                            result_cred.expire_time or "(未勾选30天)")
                res = self._http_auth_and_tcp_login(
                    result_cred.account, result_cred.password)
                if res.success:
                    return res
                # 缓存凭证鉴权失败（服务器端已失效）→ 清缓存，回退扫码
                logger.warning("缓存凭证登录失败 (%s)，清缓存并回退扫码...", res.error)
                _clear_cache(cache_path)
            else:
                logger.info("缓存凭证已确定过期，需要重新扫码")

        # ---- 2. 回退到扫码 ----
        return self.connect_with_qrcode(
            timeout=qr_timeout, png_path=png_path, cache_path=cache_path)

    @staticmethod
    def _clear_cache(cache_path: str | None = None) -> None:
        """删除凭证缓存文件（凭证已失效时调用）。"""
        from .qr_login import default_cache_path
        path = cache_path or default_cache_path()
        try:
            os.remove(path)
            logger.info("已清除过期凭证缓存: %s", path)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning("清除缓存失败（不影响登录）: %s", e)

    def connect_with_passport64(self, passport64: str) -> LoginResult:
        """用外部 Passport64 直接登录 8901（绕过 HTTP 鉴权）。

        通常用 ``connect()`` 即可——它会调用 ``build_passport64`` 自动生成
        有行情权限的 Passport64（已复刻 hexin 的字段过滤逻辑，无需抓包）。

        本方法用于特殊场景：已有现成 Passport64（如从 hexin 抓包提取、或
        外部缓存）时，跳过 HTTP 鉴权直接复用。

        Args:
            passport64: hexin login 帧里的完整 Passport64（base64 字符串）

        Returns:
            LoginResult。成功后 self._sock 可用于 list_quotes()。
        """
        login_body = build_login_body_pc(passport64, self.mac64)
        return self._do_tcp_login_raw(login_body, passport_fields={})

    def _http_auth_and_tcp_login(self, account: str, password: str) -> LoginResult:
        """用 account+password 走 HTTP 三步鉴权 → 8901 TCP login。

        connect_with_qrcode / connect_cached 共用此方法。
        """
        try:
            self._auth = full_http_auth(account, password, self.imei)
            passport_fields = parse_passport_fields(self._auth["passport_bytes"])
            logger.info("HTTP 鉴权成功（account=%s），passport 含 %d 个字段",
                        account[:6] + "***", len(passport_fields))
        except Exception as e:
            logger.error("HTTP 鉴权失败（account=%s）: %s", account[:6] + "***", e)
            return LoginResult(success=False, error="http_auth_failed", detail=str(e))

        self._init_blocks()
        return self._do_tcp_login(passport_fields, max_retries=1)

    def _do_tcp_login(self, passport_fields: dict) -> LoginResult:
        """构造 PC login 帧并连 8901（connect / connect_with_qrcode 共用）。

        前置条件：self._auth 已通过 full_http_auth 设置。
        """
        # ---- 构造 PC login 帧 ----
        passport64 = build_passport64(self._auth)
        login_body = build_login_body_pc(passport64, self.mac64)
        logger.debug("PC login 帧构造完成，body %d 字节", len(login_body))
        return self._do_tcp_login_raw(login_body, passport_fields)

    def _do_tcp_login_raw(self, login_body: bytes,
                          passport_fields: dict) -> LoginResult:
        """连 8901 发送已构造的 login 帧（多 IP 冗余，逐个尝试）。

        _do_tcp_login / connect_with_passport64 共用此方法。

        VerifyCode=-1 不是账号级限流（实测同账号连不同 IP 第2次 -1 但第3次 0），
        而是特定服务器实例的临时状态。遇到 -1 自动换下一个 host 重试。
        hexin 客户端连 7 个 IP 并发所以不受影响。
        """
        last_err = ""
        for host in MARKET_HOSTS:
            try:
                logger.info("尝试连接 %s:%d ...", host, MARKET_PORT)
                sock = socket.create_connection((host, MARKET_PORT), timeout=15)
                sock.sendall(encode_frame(login_body) + b"\n")
                resp_body = read_frame(sock)
                result = parse_login_response(resp_body)

                verify_code = result.get("VerifyCode", "?")
                logger.info("%s:%d 响应 VerifyCode=%s", host, MARKET_PORT, verify_code)

                if verify_code == "0":
                    self._sock = sock
                    self._start_heartbeat()
                    logger.info("✓ 登录成功 (%s:%d)", host, MARKET_PORT)
                    return LoginResult(
                        success=True,
                        verify_code=verify_code,
                        server=f"{host}:{MARKET_PORT}",
                        reply_fields=result,
                        passport_fields=passport_fields,
                    )
                else:
                    # 连上了、收到响应了，但 VerifyCode 非 0
                    sock.close()
                    # VerifyCode=-1 不是账号级限流（实测同账号连不同 IP 第2次-1
                    # 但第3次又 0），而是特定服务器实例的临时状态/会话冲突。
                    # hexin 客户端连 7 个 IP 并发所以不限流。策略：换下一个 host 立即重试。
                    if verify_code == "-1":
                        logger.warning("%s:%d VerifyCode=-1，换下一个 host 重试...",
                                       host, MARKET_PORT)
                        continue  # 尝试下一个 host，不直接失败
                    logger.warning("%s:%d 登录被拒 (VerifyCode=%s)", host, MARKET_PORT, verify_code)
                    return LoginResult(
                        success=False,
                        verify_code=verify_code,
                        server=f"{host}:{MARKET_PORT}",
                        reply_fields=result,
                        passport_fields=passport_fields,
                        error="login_rejected",
                    )
            except (socket.timeout, ConnectionError, OSError) as e:
                last_err = f"{host}: {e}"
                logger.warning("连接 %s 失败: %s", host, e)
                continue

        return LoginResult(success=False, error="all_hosts_failed", detail=last_err)

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

        前置条件：已 connect() 成功（self._sock 存在）。
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
        if self._sock is None:
            raise RuntimeError("未登录，请先 connect() / connect_cached()")

        frame = build_list_quote_query(codes, market=market, datatype=datatype,
                                       pageid=pageid)
        self._sock.settimeout(timeout)
        # 每帧后跟 b"\n"（2026-07-17 实时抓包确认：hexin 每个帧 trailing 都是 0a，
        # login/行情/心跳帧无一例外；不加 \n 服务器不响应）。
        # sendall 加锁，避免与心跳线程交错。
        with self._sock_lock:
            if self._sock:
                self._sock.sendall(frame + b"\n")

        # 循环读帧，跳过 CodeListSize/MarketTime 等文本帧，取首个 hd 数据帧。
        # 最多读 8 帧避免无限等待（8901 通常 1-3 帧内出数据）。
        for _ in range(8):
            resp = read_frame(self._sock)
            if b"hd3.1\x00" in resp:
                recs = parse_hd3_response(resp)
                if recs:
                    return recs
                # hd3.1 标记在但解析失败（非 BitRLE 变体）→ 继续读下一帧
                logger.warning("收到 hd3.1 帧但解析为空（可能非 BitRLE 变体），"
                               "原始头 24B: %s", resp[:24].hex(" "))
                continue
            if b"hd1.0" in resp:
                recs = parse_hd1_response(resp)
                if recs:
                    return recs
                logger.warning("收到 hd1.0 帧但解析为空，原始头 24B: %s",
                               resp[:24].hex(" "))
                continue
            # 文本帧（CodeListSize= 等），跳过
            logger.debug("跳过非数据帧: %s",
                         resp[:40].decode("gbk", errors="replace")[:40])
        logger.warning("list_quotes: 8 帧内未找到 hd 数据帧")
        return []

    def stock_list(
        self,
        timeout: float = 30.0,
    ) -> list[dict]:
        """获取全市场股票代码列表（沪深+北交所+新三板+基金，~7400 条）。

        通过重放 hexin 启动序列的关键请求段（subreal×8 + CodeList 1B0987 + init），
        触发服务器下发全量代码表（dc≈7422, unk=0x18, hs=71 的 hd3.1 帧）。
        这是 hexin 启动时加载全量代码表的同一机制（冷启动抓包 stream 44 确认）。

        ⚠ 单独发 init 请求**不会**触发全量下发（服务器只返回配置帧）。
        必须重放完整的 subreal + 特殊 CodeList 订阅序列，服务器才会在登录连接上
        推送 dc≈7422 的全量 hd3.1 帧。本方法用 ``data/stock_list_replay.bin``
        里固化的 4 个请求段（提取自 cold_start.pcap stream 44 帧1619/1965/2308/2481）。

        ⚠ 响应**不含股票名称**（dt55 字段全 0）。名称走单独的 upstockname 请求，
        尚未实现。返回的 stocks 里 name 恒为 ""。

        Args:
            timeout: 收尾读取的总时长（秒）。重放后服务器陆续推送，需等全量帧到达。

        Returns:
            list[dict]，每项 ``{"code": "600000", "name": ""}``。
            约 7400 条，按 dt5 代码字段顺序（通常代码升序）。

        Raises:
            RuntimeError: 未登录。
        """
        if self._sock is None:
            raise RuntimeError("未登录，请先 connect() / connect_cached()")

        # 加载重放段（4 个请求 segment，提取自 cold_start.pcap stream 44）
        replay_path = os.path.join(os.path.dirname(__file__), "data",
                                   "stock_list_replay.bin")
        if not os.path.exists(replay_path):
            logger.error("stock_list: 重放数据文件不存在 %s", replay_path)
            return []
        with open(replay_path, "rb") as f:
            data = f.read()
        n = int.from_bytes(data[:4], "little")
        off = 4
        segments = []
        for _ in range(n):
            ln = int.from_bytes(data[off:off+4], "little")
            off += 4
            segments.append(data[off:off+ln])
            off += ln

        best_stocks: list[dict] = []
        full_dc = 0
        # 重放期间持锁，并临时禁用心跳避免干扰（如果心跳开着）
        with self._sock_lock:
            sock = self._sock
            # 发送 4 个请求段（间隔 0.3s 模拟 hexin 节奏）
            for i, seg in enumerate(segments):
                if sock:
                    sock.sendall(seg)
                time.sleep(0.3)
            # 读响应：短超时轮询，直到 timeout 到或拿到全量帧后再读 3s 确认
            sock.settimeout(2.0)
            t0 = time.time()
            got_full_at = None
            while True:
                if got_full_at and (time.time() - got_full_at > 3):
                    break  # 拿到全量后再读 3s 确认无更大帧
                if not got_full_at and (time.time() - t0 > timeout):
                    break  # 总超时
                try:
                    resp = read_frame(sock)
                    if not resp:
                        continue
                except (socket.timeout, OSError):
                    continue
                except ValueError:
                    # read_frame 偶尔在推送帧中间解析失败（魔数碰撞），跳过
                    try:
                        sock.settimeout(1.0)
                        sock.recv(8192)
                        sock.settimeout(2.0)
                    except Exception:
                        pass
                    continue
                meta = parse_init_response(resp)
                if len(meta["stocks"]) > len(best_stocks):
                    best_stocks = meta["stocks"]
                    # 检查这一帧是否有 dc>5000 的全量帧
                    for f in meta.get("hd31_frames", []):
                        if f["unk"] == 0x18 and f["dc"] > 5000:
                            full_dc = f["dc"]
                            got_full_at = time.time()
                            break

        if best_stocks:
            logger.info("stock_list 获取 %d 条代码（全量帧 dc=%d）",
                        len(best_stocks), full_dc)
        else:
            logger.warning("stock_list: 重放后未收到全量代码表帧 "
                           "（可能服务器实例未响应，重连换 IP 重试）")
        return best_stocks

    # ── 自定义板块/自选股管理（门面方法，委托给 BlockManager）──

    def _ensure_blocks(self):
        if self._blocks is None:
            raise RuntimeError("板块功能未初始化，请先 connect()")

    @property
    def blocks(self):
        """直接暴露 BlockManager（高级用法）。未初始化时抛 RuntimeError。"""
        self._ensure_blocks()
        return self._blocks

    def list_groups(self):
        """列出所有自定义板块/分组。"""
        self._ensure_blocks()
        return self._blocks.list_groups()

    def get_group(self, name: str, *, refresh: bool = False):
        """获取指定分组的成分股。refresh=True 强制刷新缓存。"""
        self._ensure_blocks()
        return self._blocks.get_group(name, refresh=refresh)

    def add_group(self, name: str) -> str:
        """新建自定义分组，返回分组 ID。"""
        self._ensure_blocks()
        return self._blocks.add_group(name)

    def delete_group(self, name: str) -> None:
        """删除自定义分组。"""
        self._ensure_blocks()
        return self._blocks.delete_group(name)

    def share_group(self, name: str, valid_time: int = 604800):
        """分享分组（返回分享信息）。valid_time 默认 7 天。"""
        self._ensure_blocks()
        return self._blocks.share_group(name, valid_time)

    def add_stock(self, group: str, symbols):
        """向分组添加股票（symbols 为代码字符串或列表）。"""
        self._ensure_blocks()
        return self._blocks.add_stock(group, symbols)

    def remove_stock(self, group: str, symbols):
        """从分组移除股票。"""
        self._ensure_blocks()
        return self._blocks.remove_stock(group, symbols)

    def get_self_stocks(self):
        """获取「我的自选」成分股。"""
        self._ensure_blocks()
        return self._blocks.get_self_stocks()

    def query_dynamic_plate(self, condition: str, num: int = 3000):
        """动态板块查询（condition 为选股表达式），返回成分股代码列表。"""
        self._ensure_blocks()
        return self._blocks.query_dynamic_plate(condition, num)

    def list_dynamic_plates(self):
        """列出所有动态板块及其成分股（云端快照）。"""
        self._ensure_blocks()
        return self._blocks.list_dynamic_plates()

    # ── 短线精灵（异动，9601 端口 qurealorder）──

    def _connect_realorder_server(self) -> None:
        """懒连接 9601 短线精灵服务（passport64 登录）。

        用 PC 版 login 帧（build_login_body_pc）登录，VerifyCode=0 则存 socket。
        前置条件：self._auth 已设置。
        """
        if self._realorder_sock or self._auth is None:
            return
        try:
            passport64 = build_passport64(self._auth)
            login_body = build_login_body_pc(passport64, self.mac64)
            sock = socket.create_connection((REALORDER_HOST, REALORDER_PORT), timeout=15)
            sock.sendall(encode_frame(login_body) + b"\n")
            resp = read_frame(sock)
            result = parse_login_response(resp)
            if result.get("VerifyCode") == "0":
                self._realorder_sock = sock
                logger.info("9601 短线精灵服务连接成功 (%s:%d)", REALORDER_HOST, REALORDER_PORT)
            else:
                sock.close()
                logger.warning("9601 登录失败: VerifyCode=%s", result.get("VerifyCode"))
        except Exception as e:
            logger.warning("9601 短线精灵服务连接失败: %s", e)

    # ── 心跳（后台线程，维持 8901/9601 长连接）──

    def _start_heartbeat(self) -> None:
        """启动心跳后台线程（connect 成功后自动调用）。

        8901 每 3 秒、9601 每 30 秒（若已连接）。daemon 线程，主进程退出时自动结束。
        enable_heartbeat=False 时不启动（用于对比测试）。
        """
        if not self.enable_heartbeat:
            return
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return  # 已在运行
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="ths-heartbeat", daemon=True)
        self._heartbeat_thread.start()
        logger.debug("心跳线程已启动")

    def stop_heartbeat(self) -> None:
        """停止心跳线程（disconnect 时自动调用）。"""
        self._heartbeat_stop.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=5)
        self._heartbeat_thread = None

    def _heartbeat_loop(self) -> None:
        """心跳循环：8901 每 3 秒、9601 每 30 秒（10 个 3 秒周期）。

        用 _heartbeat_stop.wait(3) 阻塞，被 set 时立即退出。异常只 warning 不中断。
        """
        tick = 0
        while not self._heartbeat_stop.is_set():
            # 等 3 秒（或被 stop 唤醒立即退出）
            if self._heartbeat_stop.wait(3.0):
                break
            tick += 1
            # 8901 心跳（每 3 秒）
            if self._sock:
                try:
                    self._hb_seq_8901 += 1
                    with self._sock_lock:
                        if self._sock:
                            self._sock.sendall(build_heartbeat_8901(self._hb_seq_8901) + b"\n")
                except OSError as e:
                    logger.debug("8901 心跳发送失败（不影响查询）: %s", e)
            # 9601 心跳（每 30 秒 = 每 10 个 tick）
            if tick % 10 == 0 and self._realorder_sock:
                try:
                    self._hb_seq_9601 += 1
                    with self._realorder_lock:
                        if self._realorder_sock:
                            self._realorder_sock.sendall(
                                build_heartbeat_9601(self._hb_seq_9601) + b"\n")
                except OSError as e:
                    logger.debug("9601 心跳发送失败（不影响查询）: %s", e)

    def _realorder_query(self, body: bytes) -> bytes:
        """在 9601 连接上发查询，返回原始响应。"""
        if not self._realorder_sock:
            self._connect_realorder_server()
        if not self._realorder_sock:
            raise RuntimeError("9601 短线精灵服务未连接")
        with self._realorder_lock:
            self._realorder_sock.sendall(encode_frame(body) + b"\n")
            self._realorder_sock.settimeout(15)
            return read_frame_realorder(self._realorder_sock)

    def dxjl_page(self, market: int, endtime_us: int) -> list[dict]:
        """获取短线精灵单页数据（9601，method=qurealorder）。

        Args:
            market: 市场代码，32=深 16=沪。
            endtime_us: 微秒时间戳游标（取此时间之前的记录）。

        Returns:
            list[dict]，每项含 时间(微秒戳)/市场/代码/异动类型/异动编码/金额/涨跌幅。
        """
        try:
            self._instance += 1
            body = build_qurealorder_query(self._instance, market, endtime_us)
            resp = self._realorder_query(body)
            return parse_qurealorder_response(resp, str(market))
        except Exception as e:
            logger.error("dxjl_page 查询失败: %s", e)
            return []

    def dxjl_latest(self, markets: tuple = (32, 16)) -> list[dict]:
        """获取短线精灵最新一页（沪深）。

        Args:
            markets: 市场元组，默认 (32, 16) = 深沪。

        Returns:
            list[dict]，按时间倒序（最新在前）。非交易时段可能为空。
        """
        now_us = int(time.time() * 1_000_000)
        all_recs = []
        for mk in markets:
            all_recs.extend(self.dxjl_page(mk, now_us))
        all_recs.sort(key=lambda r: r["时间"], reverse=True)
        return all_recs

    def dxjl_history(self, pages: int = 5, markets: tuple = (32, 16)) -> list[dict]:
        """翻页获取短线精灵历史数据（endtime 游标分页）。

        翻页机制：第 N+1 页的 endtime = 第 N 页最早记录的时间戳。

        Args:
            pages: 翻页数。
            markets: 市场元组，默认 (32, 16) = 深沪。

        Returns:
            list[dict]，按时间倒序。
        """
        now_us = int(time.time() * 1_000_000)
        all_recs = []
        cursor = now_us
        for _ in range(pages):
            page_recs = []
            for mk in markets:
                page_recs.extend(self.dxjl_page(mk, cursor))
            if not page_recs:
                break
            page_recs.sort(key=lambda r: r["时间"])
            all_recs.extend(page_recs)
            cursor = page_recs[0]["时间"]
        all_recs.sort(key=lambda r: r["时间"], reverse=True)
        return all_recs

    # ── 短线精灵实时推送（9601 subrealorder 订阅 + pushrealorder 接收）──

    def subscribe_realtime(self, markets: list[int] | None = None) -> None:
        """在 9601 上订阅异动推送（method=subrealorder）。

        订阅后服务器在盘中主动推送 pushrealorder 帧（实测约 1500 条异动/分钟）。
        用 receive_pushes() 接收推送数据。

        抓包确认（2026-07-17 hexin stream 9）：在 9601 发 subrealorder，
        market=16/32/151/48，服务器 90s 内推 1125 个 pushrealorder 帧。

        Args:
            markets: 市场代码列表，默认 [16,32,151,48]（沪/深/北交所/板块）。
        """
        from .protocol import SUBREALORDER_MARKETS, build_subrealorder_query
        if markets is None:
            markets = SUBREALORDER_MARKETS
        if not self._realorder_sock:
            self._connect_realorder_server()
        if not self._realorder_sock:
            raise RuntimeError("9601 短线精灵服务未连接")
        for mk in markets:
            self._instance += 1
            body = build_subrealorder_query(self._instance, mk)
            with self._realorder_lock:
                if self._realorder_sock:
                    self._realorder_sock.sendall(encode_frame(body) + b"\n")
        logger.info("已订阅 %d 个市场的异动推送: %s", len(markets), markets)

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
        if not self._realorder_sock:
            raise RuntimeError("9601 未连接，请先 subscribe_realtime()")
        all_recs = []
        import time as _time
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            remaining = deadline - _time.time()
            if remaining <= 0:
                break
            self._realorder_sock.settimeout(min(remaining, 5.0))
            try:
                resp = read_frame_realorder(self._realorder_sock)
            except (socket.timeout, OSError):
                break
            # 只处理 pushrealorder 帧（跳过心跳响应/其他帧）
            if b"pushrealorder" not in resp:
                continue
            recs = parse_pushrealorder_response(resp)
            if callback:
                for r in recs:
                    callback(r)
            else:
                all_recs.extend(recs)
        return all_recs

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
        if not self._realorder_sock:
            raise RuntimeError("9601 未连接，请先 subscribe_realtime()")
        frame_count = 0
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            got_frame = False
            # 持锁读单帧；读完释放锁给心跳/dxjl_history 机会
            with self._realorder_lock:
                if not self._realorder_sock:
                    break
                self._realorder_sock.settimeout(min(remaining, 2.0))
                try:
                    resp = read_frame_realorder(self._realorder_sock)
                    got_frame = True
                except (socket.timeout, OSError):
                    resp = None
            if not got_frame or resp is None:
                continue
            if b"pushrealorder" not in resp:
                continue
            frame_count += 1
            if full_frame_callback:
                full_frame_callback(resp)
            recs = parse_pushrealorder_response(resp)
            if callback:
                for r in recs:
                    callback(r)
        return frame_count

    def disconnect(self) -> None:
        self.stop_heartbeat()
        for attr, lock in (("_sock", self._sock_lock),
                           ("_realorder_sock", self._realorder_lock)):
            with lock:
                sock = getattr(self, attr, None)
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    setattr(self, attr, None)
        logger.info("连接已关闭")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.disconnect()
