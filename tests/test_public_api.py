"""Public import compatibility contracts for incremental refactors."""

import thspypc


def test_top_level_client_import():
    from thspypc import THSClient

    assert THSClient.__name__ == "THSClient"


def test_protocol_compatibility_exports():
    from thspypc.protocol import (
        build_history_timeline_query,
        build_kline_query,
        decode_ths_float,
        encode_frame,
        read_frame,
    )

    assert callable(encode_frame)
    assert callable(read_frame)
    assert callable(decode_ths_float)
    assert callable(build_kline_query)
    assert callable(build_history_timeline_query)


def test_transport_compatibility_export():
    from thspypc.transport import MarketSession, OpenedConnection
    from thspypc._transport import (
        MarketSession as InternalMarketSession,
        OpenedConnection as InternalOpenedConnection,
    )

    assert MarketSession.__name__ == "MarketSession"
    assert MarketSession is InternalMarketSession
    assert OpenedConnection is InternalOpenedConnection


def test_all_declared_top_level_exports_exist():
    for name in thspypc.__all__:
        assert hasattr(thspypc, name), name


def test_protocol_reexports_use_single_codec_implementations():
    import thspypc.protocol as protocol
    from thspypc.codecs import compression, framing, hd, numeric
    from thspypc.features import (
        kline_protocol,
        history_timeline_protocol,
        auction_protocol,
        quote_protocol,
        stock_name_protocol,
        stock_list_protocol,
        timeline_protocol,
    )

    assert protocol.encode_frame is framing.encode_frame
    assert protocol.read_frame is framing.read_frame
    assert protocol.decode_ths_float is numeric.decode_ths_float
    assert protocol.normalize_8901_response is compression.normalize_8901_response
    assert protocol.parse_hd1_response is hd.parse_hd1_response
    assert protocol.parse_hd3_response is hd.parse_hd3_response
    assert (
        protocol.build_list_quote_query
        is quote_protocol.build_list_quote_query
    )
    assert (
        protocol.parse_depth_quote_response
        is quote_protocol.parse_depth_quote_response
    )
    assert protocol.build_kline_query is kline_protocol.build_kline_query
    assert (
        protocol.parse_kline_hd3_response
        is kline_protocol.parse_kline_hd3_response
    )
    assert (
        protocol.build_timeline_query
        is timeline_protocol.build_timeline_query
    )
    assert (
        protocol.parse_timeline_l2_response
        is timeline_protocol.parse_timeline_l2_response
    )
    assert (
        protocol.build_history_timeline_query
        is history_timeline_protocol.build_history_timeline_query
    )
    assert (
        protocol.parse_history_timeline_response
        is history_timeline_protocol.parse_history_timeline_response
    )
    assert protocol.build_auction_query is auction_protocol.build_auction_query
    assert (
        protocol.parse_auction_response
        is auction_protocol.parse_auction_response
    )
    assert (
        protocol.build_stock_list_query
        is stock_list_protocol.build_stock_list_query
    )
    assert (
        protocol.parse_stock_list_response
        is stock_list_protocol.parse_stock_list_response
    )
    assert protocol.build_init_query is stock_list_protocol.build_init_query
    assert (
        protocol.parse_init_response
        is stock_list_protocol.parse_init_response
    )
    assert (
        protocol.build_upstockname_request
        is stock_name_protocol.build_upstockname_request
    )
    assert (
        protocol.decode_name_frame
        is stock_name_protocol.decode_name_frame
    )
    assert (
        protocol._decode_bitrle_0x13746d0
        is compression._decode_bitrle_0x13746d0
    )
    assert (
        protocol._transpose_bitplane_0x1763410
        is compression._transpose_bitplane_0x1763410
    )
