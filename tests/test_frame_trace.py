"""离线回归：成分股连接逐帧收发转储 + 抓包对照辅助函数。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from thspypc._transport.tracing import (  # noqa: E402
    TracingSocket,
    maybe_wrap_board_socket,
    stream_frames,
)
from thspypc.protocol import encode_frame  # noqa: E402

import _compare_constituent_capture as comparator  # noqa: E402


class FakeSocket:
    def __init__(self, inbox: list[bytes] | None = None) -> None:
        self.sent: list[bytes] = []
        self._inbox = list(inbox or [])
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, _size: int) -> bytes:
        if not self._inbox:
            return b""
        return self._inbox.pop(0)

    def settimeout(self, _timeout: float | None) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def test_maybe_wrap_is_noop_without_env(monkeypatch):
    monkeypatch.delenv("THS_FRAME_DUMP_DIR", raising=False)
    sock = FakeSocket()
    wrapped = maybe_wrap_board_socket(
        sock,
        role="board_constituent_sh",
        host="10.0.0.1",
        level2=False,
    )
    assert wrapped is sock


def test_tracing_socket_records_streams_and_dump(tmp_path, monkeypatch):
    monkeypatch.setenv("THS_FRAME_DUMP_DIR", str(tmp_path))
    login = b"Ask=login\r\nPassport64=secret\r\nUserName=__manual"
    reply = b"Reply=login\r\nVerifyCode=0\r\n"
    sock = FakeSocket(
        inbox=[encode_frame(reply) + b"\n"],
    )
    wrapped = maybe_wrap_board_socket(
        sock,
        role="board_constituent_sh",
        host="10.0.0.1",
        level2=False,
    )
    assert isinstance(wrapped, TracingSocket)

    sent = encode_frame(login) + b"\n"
    wrapped.sendall(sent)
    received = wrapped.recv(65536)
    assert received == encode_frame(reply) + b"\n"
    wrapped.trace.mark_login_ok("0")
    wrapped.close()

    role_dir = tmp_path / "board_constituent_sh"
    bins = sorted(role_dir.glob("*_c2s.bin"))
    assert len(bins) == 1
    assert bins[0].read_bytes() == sent
    s2c = sorted(role_dir.glob("*_s2c.bin"))
    assert len(s2c) == 1
    assert s2c[0].read_bytes() == encode_frame(reply) + b"\n"

    meta_path = sorted(role_dir.glob("*_meta.json"))[0]
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["role"] == "board_constituent_sh"
    assert meta["host"] == "10.0.0.1"
    assert meta["level2"] is False
    assert meta["login_ok"] is True
    assert meta["verify_code"] == "0"
    assert meta["frames_c2s"] == 1
    assert meta["frames_s2c"] == 1

    frames_txt = sorted(role_dir.glob("*_frames.txt"))[0].read_text(
        encoding="utf-8"
    )
    assert "===== C->S 1 frames =====" in frames_txt
    assert "===== S->C 1 frames =====" in frames_txt
    assert "[000] C->S" in frames_txt
    assert "method=login" in frames_txt
    assert "Ask=login" in frames_txt


def test_stream_frames_splits_magic_with_trailing_newline():
    first = b"first-body"
    second = b"second-body"
    stream = encode_frame(first) + b"\n" + encode_frame(second) + b"\n"
    assert stream_frames(stream) == [first, second]
    assert stream_frames(encode_frame(first) + b"\n") == [first]


def test_mask_credentials_and_first_diff():
    body = b"Passport64=abc123\r\nMac64=xyz\r\nRest=ok"
    masked = comparator.mask_credentials(body)
    assert masked == b"Passport64=<masked>\r\nMac64=<masked>\r\nRest=ok"
    assert comparator.first_diff(b"abcdef", b"abcdef") == -1
    assert comparator.first_diff(b"abcXef", b"abcYef") == 3
    assert comparator.first_diff(b"abc", b"abcd") == 3


def test_request_items_flatten_nested_and_plain_frames():
    plain = b"\tinstid=2147483647\nmethod=subreal\nmarket=URS\npageid=5716"
    # One real nested frame: the L2 pageid register carries 3 sub-frames.
    from thspypc.features.system_blocks_protocol import (
        build_board_pageid_register,
    )

    nested = build_board_pageid_register(level2=True)
    items = comparator.request_items([plain, nested])
    assert items[0] == ("plain", plain)
    assert items[0][1] == plain
    assert items[1][0].startswith("02@")
    assert len(items) == 4  # 1 plain + 3 nested
    # Login payload is classified and masked.
    login = comparator.request_items([b"Ask=login\r\nPassport64=secret"])
    assert login[0][0] == "login"
    assert b"secret" not in login[0][1]


def test_open_board_constituent_hook_writes_login_ok_dump(
    tmp_path,
    monkeypatch,
):
    """``_open_board_channel`` 的成分股路径在转储开启时写出 login_ok 文件。"""
    import socket as socket_module
    import time
    from types import MappingProxyType

    from thspypc.client import THSClient
    from thspypc.features.auth_protocol import PC_LEVEL2_LOGIN_PROFILE
    from thspypc.services.auth import AuthMaterial

    client = THSClient("offline-user", "offline-password", enable_heartbeat=False)
    auth_info = MappingProxyType({
        "passport_bytes": b"M_hqdns=fu4.123ths.com:8901:96;48;:",
    })
    material = AuthMaterial(
        auth_info=auth_info,
        passport_fields=MappingProxyType({}),
        passport64="vgYGgAAFzDqigorqU62cDKnbV104BTU6JCFc3BNIs1mSneWw",
        profile=PC_LEVEL2_LOGIN_PROFILE,
        generation=1,
    )
    client._auth_service._current = material
    client._auth = dict(auth_info)
    hosts = ["10.0.0.9"]
    client._login_rr_offset = {
        "main": 0,
        "sh": 0,
        "sz": 0,
        "board": 0,
        "board_constituent_sh": 0,
    }
    client._probe_cache = {"board_constituent_sh": (time.time(), hosts)}

    monkeypatch.setattr(
        "thspypc.protocol.resolve_fu4_hosts",
        lambda _passport: hosts,
    )
    monkeypatch.setattr(
        "thspypc.protocol.resolve_l2_hosts_grouped",
        lambda _passport: {"sh": hosts, "sz": []},
    )
    monkeypatch.setattr(
        client,
        "_probe_fastest_hosts",
        lambda candidates, **_kwargs: list(candidates),
    )
    monkeypatch.setattr(
        "thspypc._client.connection_primitives.time.sleep",
        lambda _seconds: None,
    )
    monkeypatch.setattr(
        client,
        "_persist_ip_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setenv("THS_FRAME_DUMP_DIR", str(tmp_path))

    class FakeSocket:
        def __init__(self):
            self.sent = []
            self.closed = False

        def sendall(self, payload):
            self.sent.append(payload)

        def settimeout(self, _timeout):
            pass

        def close(self):
            self.closed = True

    monkeypatch.setattr(
        "thspypc._client.connection_primitives.socket.create_connection",
        lambda _address, timeout: FakeSocket(),
    )

    state = {"reads": 0}

    def fake_read_frame(_sock):
        state["reads"] += 1
        if state["reads"] == 1:
            return b"Reply=login\r\nVerifyCode=0\r\n"
        if state["reads"] == 2:
            return b"server-config-frame"
        raise socket_module.timeout()

    monkeypatch.setattr(client, "_connection_read_frame", fake_read_frame)

    sock = client._open_board_channel(
        constituent_side="sh",
        timeout=0.2,
    )
    assert sock is not None
    sock.close()

    role_dir = tmp_path / "board_constituent_sh"
    meta_path = sorted(role_dir.glob("*_meta.json"))
    assert meta_path
    meta = json.loads(meta_path[0].read_text(encoding="utf-8"))
    assert meta["login_ok"] is True
    assert meta["verify_code"] == "0"
    assert meta["frames_c2s"] >= 2  # login + 至少一帧引导
    assert b"Ask=login" in sorted(role_dir.glob("*_c2s.bin"))[0].read_bytes()
