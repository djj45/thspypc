from __future__ import annotations

import struct
from contextlib import contextmanager
from types import SimpleNamespace

from thspypc._client.service_facade import ServiceFacade
from thspypc.features.list_subscription_protocol import (
    LIST_SUBTYPE_MANAGE,
    LIST_SUBTYPE_QUERY,
    RANKING_LIST_COMMAND,
    RANKING_LIST_PAGEID,
)
from thspypc.services.list_subscription import ListBucketCoordinator


def _response(
    *,
    command: int,
    mode: int,
    payload: bytes,
    subtype: bytes = LIST_SUBTYPE_MANAGE,
    wire_seq: int = 0,
) -> bytes:
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, wire_seq)
    header[6:10] = subtype
    header[10] = command
    struct.pack_into("<I", header, 11, mode)
    struct.pack_into("<I", header, 18, len(payload))
    return b"\x09" + bytes(header) + struct.pack("<I", len(payload)) + payload


class _Connection:
    init_complete = True
    role = SimpleNamespace(value="sh_l2")

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    @contextmanager
    def request(self, frame, *, timeout):
        self.sent.append(frame)
        yield object()


def test_coordinator_replace_delta_and_clear_only_commit_acknowledged_state():
    replies = iter(
        [
            _response(
                command=0x5F,
                mode=0,
                payload=b"CodeListSize=2\r\n",
            ),
            _response(
                command=0x5F,
                mode=5,
                payload=b"CodeListSize=2\r\n",
            ),
            _response(
                command=0x5F,
                mode=4,
                payload=b"CodeListSize=0\r\n",
            ),
        ]
    )
    connection = _Connection()
    service = ListBucketCoordinator(frame_reader=lambda _sock: next(replies))

    assert service.replace_codes(
        connection,
        {17: ["600519", "600000"]},
        command=0x5F,
        pageid=982,
    ) == 2
    assert service.codes(connection, command=0x5F, pageid=982) == {
        "600519",
        "600000",
    }

    assert service.apply_delta(
        connection,
        command=0x5F,
        pageid=982,
        add={17: ["600036"]},
        remove={17: ["600000"]},
    ) == 2
    assert service.codes(connection, command=0x5F, pageid=982) == {
        "600519",
        "600036",
    }

    size, prior = service.clear(connection, command=0x5F, pageid=982)
    assert size == 0
    assert prior == {"600519", "600036"}
    assert service.codes(connection, command=0x5F, pageid=982) == set()
    assert b"AddCode=17(600036,);" in connection.sent[1]
    assert b"DelCode=17(600000,);" in connection.sent[1]


def test_coordinator_forwards_push_seen_before_management_ack():
    push = b"\x09\x7b\xd0\x0f\x7funsolicited"
    replies = iter(
        [
            push,
            _response(
                command=0x5F,
                mode=0,
                payload=b"CodeListSize=1\r\n",
            ),
        ]
    )
    forwarded: list[bytes] = []
    service = ListBucketCoordinator(
        frame_reader=lambda _sock: next(replies),
        unsolicited=forwarded.append,
    )

    service.replace_codes(
        _Connection(),
        {17: ["600519"]},
        command=0x5F,
        pageid=982,
    )

    assert forwarded == [push]


def test_query_matches_wire_seq_even_when_server_mode_is_metadata_word():
    payload = b"MarketTime=17(54000);\r\nhd3.1\x00payload"
    reply = _response(
        command=0x5F,
        mode=0x10010101,
        subtype=LIST_SUBTYPE_QUERY,
        wire_seq=0x1234,
        payload=payload,
    )
    service = ListBucketCoordinator(frame_reader=lambda _sock: reply)

    response = service.query(
        _Connection(),
        {17: ["600519"]},
        [7, 14, 49],
        command=0x5F,
        pageid=982,
        wire_seq=0x1234,
    )

    assert response.payload == payload
    assert response.mode_raw == 0x10010101


class _FacadeHarness(ServiceFacade):
    def __init__(self) -> None:
        self.connection = object()
        self._service_connections = SimpleNamespace(
            acquire=lambda *args, **kwargs: self.connection,
        )
        self.replace_calls = []
        self.query_calls = []
        self.delta_calls = []
        self.activations = []
        self.deactivations = []
        self._list_bucket_service = SimpleNamespace(
            replace_codes=self._replace,
            apply_delta=self._delta,
            query=self._query,
        )
        self._connection_runtime = SimpleNamespace(
            activate_ranking_depth=lambda *args: self.activations.append(args),
            deactivate_ranking_depth=lambda *args: self.deactivations.append(args),
        )

    def _replace(self, *args, **kwargs):
        self.replace_calls.append((args, kwargs))
        return 2

    def _query(self, *args, **kwargs):
        self.query_calls.append((args, kwargs))
        return object()

    def _delta(self, *args, **kwargs):
        self.delta_calls.append((args, kwargs))
        return 2

    def _run_default_service(self, _capabilities, operation):
        return operation()

    def _next_request_instance(self):
        return 0x1234


def test_facade_bulk_subscription_reuses_one_lane_and_activates_each_code():
    client = _FacadeHarness()

    size = client.ranking_depth_subscribe(
        ["600519", "600000"],
        market=17,
        callback="callback",
        query_datatype=(7, 14, 49),
    )

    assert size == 2
    assert client.replace_calls[0][0][0] is client.connection
    assert client.replace_calls[0][0][1] == {17: ("600519", "600000")}
    assert client.replace_calls[0][1]["command"] == RANKING_LIST_COMMAND
    assert client.replace_calls[0][1]["pageid"] == RANKING_LIST_PAGEID
    assert client.query_calls[0][1]["wire_seq"] == 0x1234
    assert client.activations == [
        ("600519", 17, "callback"),
        ("600000", 17, "callback"),
    ]


def test_facade_delta_accepts_single_strings_and_queries_added_codes():
    client = _FacadeHarness()

    size = client.ranking_depth_update(
        add="600009",
        remove="600000",
        market=17,
        callback="callback",
        query_datatype=(7, 14),
    )

    assert size == 2
    assert client.delta_calls[0][1]["add"] == {17: ("600009",)}
    assert client.delta_calls[0][1]["remove"] == {17: ("600000",)}
    assert client.query_calls[0][0][1] == {17: ("600009",)}
    assert client.activations == [("600009", 17, "callback")]
    assert client.deactivations == [("600000",)]
