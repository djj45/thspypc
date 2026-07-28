"""FDF envelope encoding and synchronous frame reading."""
from __future__ import annotations

import re
import socket


FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"


def encode_frame(body: bytes) -> bytes:
    """编码帧：FD FD FD FD + 8 位 ASCII hex 长度 + body。"""
    len_str = f"{len(body):08x}".encode("ascii")
    return FRAME_MAGIC + len_str + body


def read_exact(sock: socket.socket, n: int) -> bytes:
    """精确读取 n 字节。"""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接已关闭")
        buf += chunk
    return bytes(buf)


def _read_frame_body_length(sock: socket.socket) -> int:
    """读取 8 位 ASCII hex 帧长，兼容服务器偶发的第 5 个 ``0xfd``。

    正常帧头是 ``fd fd fd fd + 8字节长度``。shlv2 实测偶尔返回五个连续
    ``fd``；旧实现命中前四个后会把第五个当成长度首字节，得到
    ``b'\\xfd000007b'`` 并在 ``int(..., 16)`` 处失败。这里把长度窗口前端
    多出的原始 ``0xfd`` 逐个滑掉，再补读尾部字节。
    """
    len_str = read_exact(sock, 8)
    extra_magic = 0
    while len_str.startswith(b"\xfd"):
        extra_magic += 1
        if extra_magic > 8:
            raise ValueError("帧头连续 0xfd 过多，无法定位长度字段")
        len_str = len_str[1:] + read_exact(sock, 1)
    if not re.fullmatch(rb"[0-9A-Fa-f]{8}", len_str):
        raise ValueError(f"非法帧长度字段: {len_str!r}")
    return int(len_str, 16)


def read_frame(sock: socket.socket) -> bytes:
    """读取一帧：扫描 magic → 读 8 位 ASCII hex 长度 → 读 body。"""
    magic = bytearray()
    while True:
        b = read_exact(sock, 1)
        if not magic and b == b"\x00":
            continue
        magic += b
        if len(magic) > 4:
            magic.pop(0)
        if bytes(magic) == FRAME_MAGIC:
            break
    body_len = _read_frame_body_length(sock)
    return read_exact(sock, body_len)

