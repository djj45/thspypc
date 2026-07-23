"""
thspypc — 同花顺 Windows PC 远航版行情协议纯 Python 实现。

第一版：仅登录打通（HTTP 鉴权 → 8901 TCP login → VerifyCode 验证）。
后续按需扩展行情查询。

设备指纹（Mac64 / imei）均已逆向，完全本地自动生成，脱离抓包运行。

快速开始:
    from thspypc import THSClient

    # imei/Mac64 自动生成，只需账号密码
    with THSClient("账号", "密码") as client:
        result = client.connect()
        print("登录成功" if result.success else f"失败: {result.error}")
"""
from .client import THSClient, LoginResult
from .client import (
    market_from_code,
    default_stock_cache_path,
    save_stock_codes,
    load_stock_codes,
    is_stock_cache_expired,
)
from .protocol import (
    # 常量
    MARKET_HOSTS, MARKET_PORT, C_VERSION_PC, LIST_QUOTE_DATATYPE_DEFAULT,
    REALORDER_HOST, REALORDER_PORT, DXJL_DATATYPE, ANOMALY_MAP_DXJL,
    # 协议函数
    encode_frame, read_frame,
    full_http_auth, build_passport64,
    build_login_body_pc, parse_login_response, parse_passport_fields,
    generate_imei, generate_mac64,
    # 行情查询（个股列表）
    build_list_quote_query, parse_hd1_response, parse_hd3_response, decode_ths_float,
    # 全市场快照（空括号单请求，hfd1.0 格式）
    build_market_snapshot_query, MARKET_SNAPSHOT_MARKETS, MARKET_SNAPSHOT_DATATYPE,

    # 股票列表（全市场代码表）
    build_stock_list_query, parse_stock_list_response, STOCK_LIST_DATATYPE,
    build_init_query, parse_init_response,
    # 短线精灵（异动）
    build_qurealorder_query, parse_qurealorder_response, read_frame_realorder,
    build_subreal_query, build_subrealorder_query, parse_pushrealorder_response,
    SUBREAL_CHANNELS, SUBREALORDER_MARKETS,
    ANOMALY_GROUP_PREFIX, build_category_id, build_datatype,
    # 心跳（keep-alive）
    build_heartbeat_8901, build_heartbeat_9601,
)
from .blocks import BlockManager, BlockAuth, StockItem, StockGroup, BlockError
from .qr_login import (
    QrLoginResult, qr_login_flow,
    save_credentials, load_credentials, is_credentials_expired, default_cache_path,
)
from .parse_hfd1 import parse_hfd1_response

__version__ = "0.1.0"
__all__ = [
    "THSClient", "LoginResult",
    "market_from_code", "default_stock_cache_path",
    "save_stock_codes", "load_stock_codes", "is_stock_cache_expired",
    "MARKET_HOSTS", "MARKET_PORT", "C_VERSION_PC", "LIST_QUOTE_DATATYPE_DEFAULT",
    "REALORDER_HOST", "REALORDER_PORT", "DXJL_DATATYPE", "ANOMALY_MAP_DXJL",
    "encode_frame", "read_frame",
    "full_http_auth", "build_passport64",
    "build_login_body_pc", "parse_login_response", "parse_passport_fields",
    "generate_imei", "generate_mac64",
    "build_list_quote_query", "parse_hd1_response", "parse_hd3_response", "decode_ths_float",
    "build_market_snapshot_query", "MARKET_SNAPSHOT_MARKETS", "MARKET_SNAPSHOT_DATATYPE",
    "parse_hfd1_response",
    "build_stock_list_query", "parse_stock_list_response", "STOCK_LIST_DATATYPE",
    "build_init_query", "parse_init_response",
    "build_qurealorder_query", "parse_qurealorder_response", "read_frame_realorder",
    "build_subreal_query", "build_subrealorder_query", "parse_pushrealorder_response",
    "SUBREAL_CHANNELS", "SUBREALORDER_MARKETS",
    "ANOMALY_GROUP_PREFIX", "build_category_id", "build_datatype",
    "build_heartbeat_8901", "build_heartbeat_9601",
    "BlockManager", "BlockAuth", "StockItem", "StockGroup", "BlockError",
    "QrLoginResult", "qr_login_flow",
    "save_credentials", "load_credentials", "is_credentials_expired", "default_cache_path",
]
