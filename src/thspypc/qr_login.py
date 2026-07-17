"""
同花顺二维码扫码登录（网页版协议，PC 客户端通用）。

协议（mitmproxy 抓包逆向，upass.10jqka.com.cn，HTTPS 明文）：
  1. GET  /scan/creatCode            → {"qrid":"usk_xxx","errorCode":0}
  2. 二维码内容 = http://mobile.10jqka.com.cn/?source=PC&qrid=<qrid>
     （手机同花顺 APP 扫此 URL 即触发登录确认；无需调 /scan/creatImg 取 PNG）
  3. POST /scan/getInfoNew  轮询（~4s 一次）
     body: qrid=<qrid>&state=1&source=pc_web&page_source=web_screen&request_type=login
     未扫:   {"status":1,"res":"1","time_span":4,...}          ← 等待
     已确认: {"status":3,"account":"mx_xxx","password":"<32hex>",...}  ← 成功

拿到 account+password 后，可直接走 protocol.full_http_auth() 拿 passport。

特点：
  - creatCode 无需 cookie（实测无状态，qrid 即唯一凭证）
  - 扫码返回的 password 能直接用于 unified_login（RSA 加密后传输）
  - 完全不需要 mitmproxy/抓包，纯标准 HTTPS GET/POST
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

UPASS_BASE = "https://upass.10jqka.com.cn"
SCAN_URL_TEMPLATE = "http://mobile.10jqka.com.cn/?source=PC&qrid={qrid}"

# 浏览器 UA + 必要 header（抓包实测必需 X-Requested-With + Referer）
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass
class QrLoginResult:
    """二维码登录成功后的账号凭证。"""
    account: str       # 匿名账号，如 mx_xxxxxxxxx
    password: str      # 32 字符 hex（直接用于 unified_login，RSA 加密后传输）
    qrid: str          # 本次二维码 ID
    expire_time: int = 0   # 凭证过期 Unix 时间戳（手机勾选「30天免登录」时 > 0，否则 0）


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": _BROWSER_UA,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{UPASS_BASE}/login",
        "Origin": UPASS_BASE,
    })
    return s


def create_qrcode(session: requests.Session | None = None) -> str:
    """调 /scan/creatCode 申请一个二维码，返回 qrid（如 'usk_xxx'）。"""
    s = session or _session()
    resp = s.get(f"{UPASS_BASE}/scan/creatCode", timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if data.get("errorCode") != 0:
        raise RuntimeError(f"creatCode 失败: {data}")
    qrid = data["qrid"]
    logger.info("二维码已生成: qrid=%s", qrid)
    return qrid


def get_scan_url(qrid: str) -> str:
    """二维码扫码 URL（手机同花顺扫此 URL 触发登录确认）。"""
    return SCAN_URL_TEMPLATE.format(qrid=qrid)


def poll_scan_status(
    qrid: str,
    session: requests.Session | None = None,
    timeout: float = 180.0,
    interval: float = 4.0,
    on_status: "callable | None" = None,
) -> QrLoginResult:
    """轮询 /scan/getInfoNew，阻塞直到扫码确认成功。

    Args:
        qrid: create_qrcode 返回的二维码 ID
        timeout: 最长等待秒数（二维码默认有效期 ~120s）
        interval: 轮询间隔（服务器建议 time_span=4s）
        on_status: 可选回调 fn(status_dict)，每次轮询后调用，用于 UI 提示

    Returns:
        QrLoginResult(account, password, qrid)

    Raises:
        TimeoutError: 超时未扫码
        RuntimeError: 服务器返回错误 / 二维码过期
    """
    s = session or _session()
    body = {
        "qrid": qrid,
        "state": "1",
        "source": "pc_web",
        "page_source": "web_screen",
        "request_type": "login",
    }
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        resp = s.post(f"{UPASS_BASE}/scan/getInfoNew", data=body, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("status")
        if on_status:
            on_status(data)
        if data.get("errorCode") not in (0, None):
            raise RuntimeError(f"getInfoNew 错误: {data}")
        if status == 3:
            # 扫码确认成功
            account = data["account"]
            password = data["password"]
            expire_time = int(data.get("expireTime", 0) or 0)
            logger.info("扫码登录成功: account=%s, expire_time=%s", account,
                        expire_time if expire_time else "(一次性)")
            return QrLoginResult(account=account, password=password,
                                 qrid=qrid, expire_time=expire_time)
        elif status == 1:
            # 等待扫码
            if data.get("expired") == 0:
                raise RuntimeError("二维码已过期，请重新生成")
            logger.debug("等待扫码... (attempt %d, status=%s)", attempt, status)
        else:
            # 其他状态（2=已扫待确认？）记录后继续
            logger.debug("状态 status=%s (attempt %d): %s", status, attempt, data)
        time.sleep(interval)
    raise TimeoutError(f"扫码超时（{timeout}s 内未确认）")


def render_qr_ascii(url: str, *, dark_background: bool = True) -> str:
    """把 URL 渲染成终端二维码（dQR 方案：██/空格，不合并行）。

    每个二维码模块映射为 2 个字符，每模块 = 2 字符宽 × 1 行高。
    终端字符高宽比 ≈ 2:1 → 每模块物理尺寸 ≈ 正方形，整体不扭曲，手机可扫。

    颜色映射（让终端输出和标准二维码一样都是「白底黑码」）：
        深色终端 (dark_background=True, 默认):
            QR 白模块 → '██' (亮色字符填充)
            QR 黑模块 → '  ' (空格，露出深色背景)
        浅色终端 (dark_background=False):
            QR 白模块 → '  ' (空格，露出浅色背景)
            QR 黑模块 → '██' (亮色字符填充)

    不用 Unicode 半块字符（▀▄）——它们在很多 Windows 终端字体里渲染高度不准。
    不重复行——那样会让二维码纵向拉长一倍（物理比例 1:2，扫不出）。
    用 qrcode.get_matrix() 直接拿 bool 矩阵，无需 PIL 依赖。

    参考：dshowing/dQR（box_size=10 PIL 像素采样方案的等价精简版）。
    """
    import qrcode

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,  # 25%，和服务器 PNG 一致
        box_size=1,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    matrix = qr.get_matrix()  # cell=True=黑模块, False=白模块

    if dark_background:
        # 深色终端：白模块→██(亮), 黑模块→空格(暗) → 视觉白底黑码
        block_for = {True: "  ", False: "██"}
    else:
        # 浅色终端：黑模块→██(深色字), 白模块→空格(亮底) → 视觉白底黑码
        block_for = {True: "██", False: "  "}

    lines = []
    for row in matrix:
        lines.append("".join(block_for[cell] for cell in row))
    return "\n".join(lines)


def save_qr_png(url: str, path: str) -> None:
    """把扫码 URL 渲染成 PNG 文件保存（备用：终端扫不了时用图片）。"""
    import qrcode
    img = qrcode.make(url)
    img.save(path)


def fetch_qr_png(qrid: str, session: requests.Session | None = None) -> bytes:
    """从服务器 /scan/creatImg 拉二维码 PNG（和网页版完全相同的图）。"""
    s = session or _session()
    resp = s.get(f"{UPASS_BASE}/scan/creatImg", params={"qrid": qrid}, timeout=15)
    resp.raise_for_status()
    return resp.content


def qr_login_flow(timeout: float = 180.0, show_qr: bool = True,
                  png_path: str | None = None) -> QrLoginResult:
    """完整的二维码登录流程：生成二维码 → 显示 → 轮询等待扫码。

    Args:
        timeout: 等待扫码的最长秒数
        show_qr: 是否在终端打印 ASCII 二维码
        png_path: 若给定，同时把二维码 PNG 存到该路径（终端扫不了时用图片扫）

    Returns:
        QrLoginResult(account, password, qrid)
    """
    session = _session()
    qrid = create_qrcode(session)
    url = get_scan_url(qrid)
    if show_qr:
        print("\n请用手机「同花顺 APP」扫描下方二维码登录：\n")
        print(render_qr_ascii(url))
        print(f"\n（二维码 URL: {url}）")
    if png_path:
        # 优先用服务器返回的 PNG（手机肯定能扫）
        try:
            png = fetch_qr_png(qrid, session)
            with open(png_path, "wb") as f:
                f.write(png)
            print(f"（二维码图片已存: {png_path}，终端扫不了时可用此图）")
        except Exception as e:
            # 退化：用 qrcode 库本地生成
            save_qr_png(url, png_path)
            print(f"（本地生成二维码图片: {png_path}）")
    print()
    return poll_scan_status(qrid, session, timeout=timeout)


# ---------------------------------------------------------------------------
# 扫码凭证缓存（自适应免登录）
# ---------------------------------------------------------------------------
#
# 抓包验证（compare_remember.py）发现：手机端勾选「30天免登录」时，getInfoNew
# 返回的 account+password 与不勾选完全相同，唯一区别是多了 expireTime 字段
# （Unix 时间戳，约 30 天后）。expireTime=0 表示服务器未明确有效期。
#
# 自适应策略：不靠时间预判凭证是否有效，而是「先试再说」——
#   connect_cached() 每次都用缓存凭证尝试登录，失败（服务器已失效）才清缓存回退扫码。
#   这样无论服务器实际让凭证活多久，都能自动适应，用户无需关心是否勾选了 30 天。
# is_credentials_expired() 只挡「确定已死」的凭证（expireTime 明显过期），
# 避免对肯定失效的凭证发起无谓的网络请求。

import json
import os
import time

# 缓存文件保护期：即使 expireTime=0（未勾选30天），凭证存盘后这段时间内认为值得一试。
# 超过此时间且 expireTime=0 的凭证，直接视为过期（省一次注定失败的网络请求）。
# 默认 3 天——比真实有效期保守，但比 1 天宽裕。
_FALLBACK_TTL = 3 * 86400
# 留点提前量，避免凭证刚好在临界点过期：提前 1 小时视为过期。
_EXPIRY_MARGIN = 3600


def default_cache_path() -> str:
    """凭证缓存的默认路径（用户 home 目录，跨平台）。"""
    return os.path.join(os.path.expanduser("~"), ".ths_qr_credentials.json")


def save_credentials(result: QrLoginResult, path: str | None = None) -> str:
    """把扫码凭证存盘，供下次免扫码复用。

    存储内容：account / password / qrid / expire_time / saved_at。
    存到用户 home 目录的 .ths_qr_credentials.json（或指定 path）。

    Returns:
        实际写入的文件路径。
    """
    path = path or default_cache_path()
    data = {
        "account": result.account,
        "password": result.password,
        "qrid": result.qrid,
        "expire_time": result.expire_time,
        "saved_at": int(time.time()),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    logger.info("扫码凭证已缓存: %s (account=%s, expire=%s)", path,
                result.account, result.expire_time or "(未勾选30天)")
    return path


def load_credentials(path: str | None = None) -> tuple[QrLoginResult, int] | None:
    """读取缓存的扫码凭证。不存在或格式错误时返回 None。

    Returns:
        (QrLoginResult, saved_at) 或 None。saved_at 是存盘时的 Unix 时间戳。
    """
    path = path or default_cache_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = QrLoginResult(
            account=data["account"],
            password=data["password"],
            qrid=data.get("qrid", ""),
            expire_time=int(data.get("expire_time", 0) or 0),
        )
        saved_at = int(data.get("saved_at", 0) or 0)
        return result, saved_at
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("凭证缓存读取失败（将忽略）: %s", e)
        return None


def is_credentials_expired(result: QrLoginResult, saved_at: int = 0,
                           now: int | None = None) -> bool:
    """判断缓存的凭证是否「确定已过期」（不值得再试）。

    自适应策略下采用宽松判断——只挡明确失效的凭证，其余一律放行让 connect_cached 试：
      - expire_time > 0（勾选了30天）：超过 expire_time + 余量 → 确定过期
      - expire_time = 0（未勾选30天）：超过 saved_at + _FALLBACK_TTL(3天) → 确定过期
      - 其他情况 → 未过期（值得一试）

    注意：返回 True 不代表凭证一定无效，只是「不值得再试」。
    真正的有效性由 connect_cached 尝试登录后才知道。
    """
    now = now or int(time.time())
    if result.expire_time > 0:
        return now >= result.expire_time - _EXPIRY_MARGIN
    # 未勾选30天：按存盘时间算，超过保护期才算确定过期
    if saved_at > 0:
        return now >= saved_at + _FALLBACK_TTL
    # 没有 saved_at 信息（异常情况），保守放行让试一次
    return False
