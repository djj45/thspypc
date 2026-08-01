"""Opt-in per-frame wire tracing for board/constituent sockets.

Set ``THS_FRAME_DUMP_DIR=<dir>`` to wrap every socket opened by
:meth:`thspypc._client.connection_primitives.ConnectionPrimitives._open_board_channel`
in a :class:`TracingSocket`.  The wrapper records raw directional bytes
(``*_c2s.bin`` / ``*_s2c.bin``), a readable per-frame dump
(``*_frames.txt``) and metadata (``*_meta.json``).  When the variable is
unset the wrap is a no-op and the hot path is untouched.

Raw stream files preserve the exact wire bytes so they can be compared
byte-by-byte against the clean client captures (see
``tests/_compare_constituent_capture.py``).  The frame dump uses the same
MAGIC-split convention as the capture analysis tools so both sides parse
identically.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"
_SEQ = itertools.count(1)


def stream_frames(stream: bytes) -> list[bytes]:
    """Split a raw directional stream into outer FD frame bodies.

    Mirrors the split used by the capture tools (``tests/*_analyze_clean*``):
    every ``fd fd fd fd`` boundary begins an 8-hex-digit ASCII length followed
    by the body.  A trailing ``0x0a`` separator is left to the next segment.
    """
    frames: list[bytes] = []
    for part in stream.split(FRAME_MAGIC):
        if len(part) < 8:
            continue
        try:
            size = int(part[:8], 16)
        except ValueError:
            continue
        frames.append(part[8 : 8 + size])
    return frames


def _frame_hint(body: bytes) -> dict[str, Any]:
    text = body.decode("gbk", errors="replace")
    method = re.search(r"method=(\w+)", text)
    if b"Ask=login" in body:
        method_text = "login"
    elif b"Reply=login" in body:
        method_text = "login-reply"
    else:
        method_text = method.group(1) if method else ""
    page = re.search(r"pageid=(\d+)", text)
    codes = 0
    for _market, values in re.findall(r"CodeList=(-?\d+)\(([^)]*)\)", text):
        codes += len([code for code in values.split(",") if code])
    return {
        "method": method_text,
        "pageid": page.group(1) if page else "",
        "codes": codes,
    }


class FrameTracer:
    """Accumulate one socket's directional bytes and write dumps on close."""

    def __init__(
        self,
        root: Path,
        *,
        role: str,
        host: str,
        level2: bool,
    ) -> None:
        stamp = time.strftime("%Y%m%d_%H%M%S")
        safe_host = host.replace(".", "_").replace(":", "_")
        self.dir = root / role
        self.dir.mkdir(parents=True, exist_ok=True)
        self.prefix = f"{stamp}_{next(_SEQ):03d}_{safe_host}"
        self._lock = threading.Lock()
        self._closed = False
        self._events: list[dict[str, Any]] = []
        self._started = time.monotonic()
        self._last_ts = self._started
        self._c2s_buf = bytearray()
        self._s2c_buf = bytearray()
        self._c2s_handle = (self.dir / f"{self.prefix}_c2s.bin").open("ab")
        self._s2c_handle = (self.dir / f"{self.prefix}_s2c.bin").open("ab")
        self.meta: dict[str, Any] = {
            "role": role,
            "host": host,
            "level2": level2,
            "login_ok": False,
            "verify_code": None,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "c2s_bytes": 0,
            "s2c_bytes": 0,
            "events": 0,
        }

    def _append(self, handle, buf: bytearray, direction: str, data: bytes) -> None:
        with self._lock:
            if self._closed:
                return
            handle.write(data)
            handle.flush()
            buf += data
            now = time.monotonic()
            self._events.append(
                {
                    "dir": direction,
                    "dt": round(now - self._last_ts, 6),
                    "bytes": len(data),
                }
            )
            self._last_ts = now
            self.meta[f"{direction}_bytes"] += len(data)
            self.meta["events"] += 1

    def send(self, data: bytes) -> None:
        self._append(self._c2s_handle, self._c2s_buf, "c2s", data)

    def recv(self, data: bytes) -> None:
        self._append(self._s2c_handle, self._s2c_buf, "s2c", data)

    def mark_login_ok(self, verify_code: str) -> None:
        with self._lock:
            self.meta["login_ok"] = True
            self.meta["verify_code"] = verify_code

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            c2s_frames = stream_frames(bytes(self._c2s_buf))
            s2c_frames = stream_frames(bytes(self._s2c_buf))
            self._c2s_handle.close()
            self._s2c_handle.close()
        self.meta["closed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.meta["duration_s"] = round(time.monotonic() - self._started, 3)
        self.meta["frames_c2s"] = len(c2s_frames)
        self.meta["frames_s2c"] = len(s2c_frames)
        self._write_frames(c2s_frames, s2c_frames)
        self._write_meta()

    def _write_frames(
        self,
        c2s_frames: list[bytes],
        s2c_frames: list[bytes],
    ) -> None:
        lines = [
            f"# role={self.meta['role']} host={self.meta['host']} "
            f"level2={self.meta['level2']} login_ok={self.meta['login_ok']}",
            f"# started={self.meta['created_at']} closed={self.meta['closed_at']} "
            f"duration={self.meta['duration_s']}s "
            f"c2s={self.meta['c2s_bytes']}B s2c={self.meta['s2c_bytes']}B",
        ]
        for direction, frames in (("C->S", c2s_frames), ("S->C", s2c_frames)):
            lines.append(f"===== {direction} {len(frames)} frames =====")
            for index, body in enumerate(frames):
                hint = _frame_hint(body)
                digest = hashlib.sha256(body).hexdigest()[:16]
                lines.append(
                    f"[{index:03d}] {direction} {len(body)}B sha256={digest} "
                    f"method={hint['method'] or '-'} pageid={hint['pageid'] or '-'} "
                    f"codes={hint['codes']}"
                )
                hex_head = body[:64].hex(" ")
                if len(body) > 64:
                    hex_head += f" ... (+{len(body) - 64}B)"
                lines.append("  hex: " + hex_head)
                text = body.decode("gbk", errors="replace")
                shown = text[:400].replace("\r", "\\r").replace("\n", "\\n")
                if len(text) > 400:
                    shown += f" ... (+{len(text) - 400} chars)"
                lines.append("  text: " + repr(shown))
        (self.dir / f"{self.prefix}_frames.txt").write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

    def _write_meta(self) -> None:
        (self.dir / f"{self.prefix}_meta.json").write_text(
            json.dumps(self.meta, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


class TracingSocket:
    """Delegate socket passthrough while recording every send/recv byte."""

    def __init__(self, sock: Any, tracer: FrameTracer) -> None:
        self._sock = sock
        self.trace = tracer

    def sendall(self, data: bytes) -> None:
        self._sock.sendall(data)
        self.trace.send(data)

    def send(self, data: bytes) -> int:
        sent = self._sock.send(data)
        if sent:
            self.trace.send(data[:sent])
        return sent

    def recv(self, bufsize: int) -> bytes:
        data = self._sock.recv(bufsize)
        if data:
            self.trace.recv(data)
        return data

    def settimeout(self, timeout: float | None) -> Any:
        return self._sock.settimeout(timeout)

    def close(self) -> None:
        try:
            self._sock.close()
        finally:
            self.trace.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sock, name)


def maybe_wrap_board_socket(
    sock: Any,
    *,
    role: str,
    host: str,
    level2: bool,
) -> Any:
    """Wrap ``sock`` when ``THS_FRAME_DUMP_DIR`` is set; otherwise no-op."""
    root = os.environ.get("THS_FRAME_DUMP_DIR")
    if not root:
        return sock
    tracer = FrameTracer(
        Path(root),
        role=role,
        host=host,
        level2=level2,
    )
    return TracingSocket(sock, tracer)


__all__ = [
    "FRAME_MAGIC",
    "FrameTracer",
    "TracingSocket",
    "maybe_wrap_board_socket",
    "stream_frames",
]
