"""
thspypc — 同花顺 Windows PC 免费版行情协议纯 Python 实现。

提供登录、行情列表、K线、分时、竞价、五档盘口、异动与板块管理等能力。

设备指纹（Mac64 / imei）均已逆向，完全本地自动生成，脱离抓包运行。

快速开始:
    from thspypc import THSClient

    # imei/Mac64 自动生成，只需账号密码
    with THSClient("账号", "密码") as client:
        result = client.connect()
        print("登录成功" if result.success else f"失败: {result.error}")
"""
from .client import THSClient, LoginResult
from .models import (
    AccountEvidence,
    AccountKind,
    AccountProfile,
    Capability,
    DepthLevel,
    DepthQuote,
    Support,
)
from .features.account_profile import (
    AccountEvidenceRecorder,
    build_account_profile,
)
from .services.auth import AuthMaterial
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
    STANDARD_REALORDER_CATEGORY_IDS, LEVEL2_ONLY_REALORDER_CATEGORY_IDS,
    ALL_REALORDER_CATEGORY_IDS,
    # 协议函数
    encode_frame, read_frame,
    full_http_auth, build_passport64,
    build_login_body_pc, build_manual_login_body, parse_login_response, parse_passport_fields,
    generate_imei, generate_mac64,
    # 行情查询（个股列表）
    build_list_quote_query, parse_hd1_response, parse_hd3_response, decode_ths_float,
    # 五档/十档盘口
    build_depth_quote_query, build_depth_ten_query,
    parse_depth_quote_response,
    DEPTH_QUOTE_DATATYPE, DEPTH_QUOTE_DATATYPE_10,
    # K线（hd1.0/hd3.1 变体，flag=0x0042/0x0046）
    parse_kline_hd1_response, parse_kline_hd3_response,
    build_kline_query, KLINE_DATATYPE,
    KLINE_PERIOD_1MIN, KLINE_PERIOD_5MIN, KLINE_PERIOD_15MIN,
    KLINE_PERIOD_30MIN, KLINE_PERIOD_60MIN,
    KLINE_PERIOD_DAY, KLINE_PERIOD_WEEK, KLINE_PERIOD_MONTH,
    KLINE_PERIOD_QUARTER, KLINE_PERIOD_YEAR,
    # 分时图（当日逐点 + 历史回忆）
    build_timeline_query, parse_timeline_response, TIMELINE_DATATYPE,
    parse_index_timeline_response, enrich_index_lead_line,
    INDEX_TIMELINE_FLAGS, INDEX_TIMELINE_MARKETS,
    build_history_timeline_query, build_normal_history_timeline_query,
    build_index_history_timeline_query,
    parse_history_timeline_response,
    HISTORY_TIMELINE_DATATYPE, HISTORY_TIMELINE_PAGEID,
    NORMAL_HISTORY_TIMELINE_DATATYPE, NORMAL_HISTORY_TIMELINE_PAGEID,
    INDEX_HISTORY_TIMELINE_DATATYPE, INDEX_HISTORY_TIMELINE_PAGEID,
    date_to_timeline_bar, timeline_bar_to_date,
    date_to_normal_timeline_bar, normal_timeline_bar_to_date,
    build_basic_auction_query, build_index_auction_context_query,
    build_index_auction_query,
    build_l2_closing_auction_query,
    build_l2_history_auction_query,
    parse_closing_auction_response, parse_index_auction_response,
    BASIC_AUCTION_PAGEID, BASIC_HISTORY_AUCTION_PAGEID,
    CLOSING_AUCTION_PERIOD, CLOSING_AUCTION_DATATYPE,
    INDEX_AUCTION_PAGEID, INDEX_CLOSING_AUCTION_CODES,
    # 实时分时推送（pageid=4214 逐 tick 快照，现价随成交跳动）
    build_snapshot_subscribe, parse_snapshot_push, is_snapshot_push,
    parse_auction_cancel_push, is_auction_cancel_push,
    is_stock_depth_envelope,
    parse_auction_depth_push, is_auction_depth_push,
    QuoteStreamNormalizer, normalize_stock_depth_push,
    parse_depth_push, parse_depth_push_records, is_depth_push,
    SNAPSHOT_PAGEID, SNAPSHOT_DATATYPE,
    # 全市场快照（空括号单请求，hfd1.0 格式）
    build_market_snapshot_query, MARKET_SNAPSHOT_MARKETS, MARKET_SNAPSHOT_DATATYPE,
    # pageid=1334 列表订阅桶（纯协议层，尚未接 service/socket）
    build_list_subscription_codes, build_list_subscription_delta,
    build_list_subscription_clear,
    build_list_subscription_query, parse_list_subscription_response,
    LIST_SUBSCRIPTION_PAGEID, LIST_SUBTYPE_MANAGE, LIST_SUBTYPE_QUERY,
    RANKING_LIST_COMMAND, RANKING_LIST_DATATYPE, RANKING_LIST_PAGEID,
    LIST_MODE_GROUP_0, LIST_MODE_QUERY, LIST_MODE_GROUP_2, LIST_MODE_GROUP_3,
    LIST_MODE_CLEAR, LIST_MODE_DELTA, ListSubscriptionResponse,

    # 股票列表（全市场代码表）
    build_full_stock_list_query, build_stock_list_query,
    build_dde_query, parse_dde_response,
    DDE_PAGEID, DDE_STANDARD_ROUTE, DDE_LEVEL2_ROUTE,
    DDE_STANDARD_MARKETS, DDE_LEVEL2_MARKETS, DDE_RESPONSE_FIELDS,
    parse_stock_list_response, STOCK_LIST_DATATYPE,
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
    "THSClient", "LoginResult", "AuthMaterial",
    "AccountEvidence", "AccountKind", "AccountProfile", "Capability", "Support",
    "AccountEvidenceRecorder", "build_account_profile",
    "DepthLevel", "DepthQuote",
    "market_from_code", "default_stock_cache_path",
    "save_stock_codes", "load_stock_codes", "is_stock_cache_expired",
    "MARKET_HOSTS", "MARKET_PORT", "C_VERSION_PC", "LIST_QUOTE_DATATYPE_DEFAULT",
    "REALORDER_HOST", "REALORDER_PORT", "DXJL_DATATYPE", "ANOMALY_MAP_DXJL",
    "STANDARD_REALORDER_CATEGORY_IDS", "LEVEL2_ONLY_REALORDER_CATEGORY_IDS",
    "ALL_REALORDER_CATEGORY_IDS",
    "encode_frame", "read_frame",
    "full_http_auth", "build_passport64",
    "build_login_body_pc", "build_manual_login_body", "parse_login_response", "parse_passport_fields",
    "generate_imei", "generate_mac64",
    "build_list_quote_query", "parse_hd1_response", "parse_hd3_response", "decode_ths_float",
    "build_depth_quote_query", "build_depth_ten_query",
    "parse_depth_quote_response",
    "DEPTH_QUOTE_DATATYPE", "DEPTH_QUOTE_DATATYPE_10",
    "parse_kline_hd1_response", "parse_kline_hd3_response",
    "build_kline_query", "KLINE_DATATYPE",
    "KLINE_PERIOD_1MIN", "KLINE_PERIOD_5MIN", "KLINE_PERIOD_15MIN",
    "KLINE_PERIOD_30MIN", "KLINE_PERIOD_60MIN",
    "KLINE_PERIOD_DAY", "KLINE_PERIOD_WEEK", "KLINE_PERIOD_MONTH",
    "KLINE_PERIOD_QUARTER", "KLINE_PERIOD_YEAR",
    "build_timeline_query", "parse_timeline_response", "TIMELINE_DATATYPE",
    "parse_index_timeline_response", "enrich_index_lead_line",
    "INDEX_TIMELINE_FLAGS", "INDEX_TIMELINE_MARKETS",
    "build_snapshot_subscribe", "parse_snapshot_push", "is_snapshot_push",
    "parse_auction_cancel_push", "is_auction_cancel_push",
    "is_stock_depth_envelope",
    "parse_auction_depth_push", "is_auction_depth_push",
    "QuoteStreamNormalizer", "normalize_stock_depth_push",
    "parse_depth_push", "parse_depth_push_records", "is_depth_push",
    "SNAPSHOT_PAGEID", "SNAPSHOT_DATATYPE",
    "build_history_timeline_query", "build_normal_history_timeline_query",
    "build_index_history_timeline_query",
    "parse_history_timeline_response",
    "HISTORY_TIMELINE_DATATYPE", "HISTORY_TIMELINE_PAGEID",
    "NORMAL_HISTORY_TIMELINE_DATATYPE", "NORMAL_HISTORY_TIMELINE_PAGEID",
    "INDEX_HISTORY_TIMELINE_DATATYPE", "INDEX_HISTORY_TIMELINE_PAGEID",
    "date_to_timeline_bar", "timeline_bar_to_date",
    "date_to_normal_timeline_bar", "normal_timeline_bar_to_date",
    "build_basic_auction_query", "build_index_auction_context_query",
    "build_index_auction_query",
    "build_l2_closing_auction_query",
    "build_l2_history_auction_query",
    "parse_closing_auction_response", "parse_index_auction_response",
    "BASIC_AUCTION_PAGEID", "BASIC_HISTORY_AUCTION_PAGEID",
    "CLOSING_AUCTION_PERIOD", "CLOSING_AUCTION_DATATYPE",
    "INDEX_AUCTION_PAGEID", "INDEX_CLOSING_AUCTION_CODES",
    "build_market_snapshot_query", "MARKET_SNAPSHOT_MARKETS", "MARKET_SNAPSHOT_DATATYPE",
    "build_list_subscription_codes", "build_list_subscription_delta",
    "build_list_subscription_clear",
    "build_list_subscription_query", "parse_list_subscription_response",
    "LIST_SUBSCRIPTION_PAGEID", "LIST_SUBTYPE_MANAGE", "LIST_SUBTYPE_QUERY",
    "RANKING_LIST_COMMAND", "RANKING_LIST_DATATYPE", "RANKING_LIST_PAGEID",
    "LIST_MODE_GROUP_0", "LIST_MODE_QUERY", "LIST_MODE_GROUP_2", "LIST_MODE_GROUP_3",
    "LIST_MODE_CLEAR", "LIST_MODE_DELTA", "ListSubscriptionResponse",
    "parse_hfd1_response",
    "build_full_stock_list_query", "build_stock_list_query",
    "build_dde_query", "parse_dde_response",
    "DDE_PAGEID", "DDE_STANDARD_ROUTE", "DDE_LEVEL2_ROUTE",
    "DDE_STANDARD_MARKETS", "DDE_LEVEL2_MARKETS", "DDE_RESPONSE_FIELDS",
    "parse_stock_list_response", "STOCK_LIST_DATATYPE",
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
