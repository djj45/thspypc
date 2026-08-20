#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""拉取 603334 逐笔真值(7169 回放),供离线破译 0x60/0x04 批量帧。

优先调用已经运行的 Web 后台，复用其唯一 THSClient/L2 socket；只有确认 8765
未监听时才创建当前进程的缓存客户端。只拉一个区间:
2026-08-20 13:19:14~13:19:37,覆盖 pcap 推送流的全部缺口(7463~7508)。

产物: captures_live/_type60_truth_603334.json
"""
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.testing import get_client  # noqa: E402


BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8765


def _backend_listening() -> bool:
    """Check the local backend without sending a market request."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex((BACKEND_HOST, BACKEND_PORT)) == 0


def _fetch_via_backend(start: datetime, end: datetime) -> list[dict]:
    query = urlencode(
        {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "market": 17,
            "pageid": 4214,
        }
    )
    url = f"http://{BACKEND_HOST}:{BACKEND_PORT}/api/superorder/603334?{query}"
    try:
        with urlopen(url, timeout=35.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read(2048).decode("utf-8", "replace")
        raise RuntimeError(
            f"Web 后台逐笔接口失败 HTTP {exc.code}: {detail}；"
            "为避免重复登录，不回退到独立客户端"
        ) from exc
    except URLError as exc:
        raise RuntimeError(
            f"Web 后台在探测后变得不可用: {exc.reason}；"
            "为避免重复登录，不回退到独立客户端"
        ) from exc


def main():
    start = datetime(2026, 8, 20, 13, 19, 14)
    end = datetime(2026, 8, 20, 13, 19, 37)

    t0 = time.time()
    if _backend_listening():
        print("检测到 127.0.0.1:8765，复用 Web 后台 THSClient")
        records = _fetch_via_backend(start, end)
    else:
        print("未检测到 Web 后台，使用当前进程唯一缓存 THSClient")
        client = get_client(ROOT / ".env")
        try:
            records = client.superorder("603334", start, end, timeout=25.0)
        finally:
            client.disconnect()
    print(f"耗时 {time.time()-t0:.1f}s, {len(records)} 条")

    out = []
    for r in records:
        out.append({
            "seq": r["seq"],
            "dt1": r["dt1"],
            "dt56_raw": r["dt56"],
            "price": r["price"],
            "dt10": r["dt10"],
            "dt13": r["dt13"],
            "dt12": r["dt12"],
            "dt74": r["dt74"],
            "dt18": r["dt18"],
        })
    path = ROOT / "captures_live" / "_type60_truth_603334.json"
    path.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"已保存 {path}")

    print(f"\n{'seq':>6} {'time':>10} {'price':>7} {'vol':>6} dir a/b/tno")
    for r in out:
        t = datetime.fromtimestamp(r["dt1"]).strftime("%H:%M:%S")
        print(f"{r['seq']:>6} {t:>10} {r['price']:>7.3f} {r['dt10']:>6} "
              f"{r['dt13']:>3} {r['dt12']:>9}/{r['dt74']:>9} tno={r['dt18']}")


if __name__ == "__main__":
    main()
