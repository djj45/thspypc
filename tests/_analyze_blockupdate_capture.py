#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""分析 frida 抓到的 BlockUpdate cloud 同步响应。

把 frida_log.jsonl 里每个 request 事务的响应体拼出来,逐个判断:
  - 5B 占位响应是不是 "无更新"
  - blockstock 的大响应(772575B)是什么格式:全量包?增量包?压缩?
"""
import base64
import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOG = ROOT / "captures_live" / "blockupdate_20260811_202014" / "frida_log.jsonl"


def load_records(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def reconstruct(records):
    """按 handle 聚合事务。返回 handle -> dict(server, verb, obj, headers, req_b64, resp_b64, query, ts)。"""
    txs = collections.OrderedDict()
    conn = {}
    for r in records:
        t = r.get("t")
        ts = r.get("ts")
        if t == "connect":
            conn[r["handle"]] = (r["server"], r["port"])
        elif t == "request":
            h = r["handle"]
            txs[h] = {
                "ts": ts,
                "handle": h,
                "server": r.get("server"),
                "port": r.get("port"),
                "verb": r.get("verb"),
                "obj": r.get("obj"),
                "headers": [],
                "req_b64": [],
                "resp_b64": [],
                "resp_len": 0,
                "query": [],
            }
        elif t == "req_headers":
            txs[r["handle"]]["headers"].append(r.get("headers", ""))
        elif t == "req_body":
            txs[r["handle"]]["req_b64"].append(r.get("b64", ""))
        elif t == "resp_body":
            tx = txs.get(r["handle"])
            if tx is not None:
                tx["resp_b64"].append(r.get("b64", ""))
                tx["resp_len"] += r.get("len", 0)
        elif t == "query_info":
            tx = txs.get(r["handle"])
            if tx is not None:
                tx["query"].append({"level": r.get("infoLevel"), "value": r.get("value")})
    return txs


def resp_bytes(tx):
    try:
        return base64.b64decode("".join(tx["resp_b64"]))
    except Exception:
        return b""


def req_bytes(tx):
    try:
        return base64.b64decode("".join(tx["req_b64"]))
    except Exception:
        return b""


def parse_obj(obj: str) -> dict:
    """解析 query string。obj 形如 /multiStorage?reqtype=download&version=... 或 /sysStorage/download/version=..."""
    out = {"path": obj}
    if "?" in obj:
        path, qs = obj.split("?", 1)
        out["path"] = path
        for kv in qs.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                out[k] = v
    else:
        # /sysStorage/download/version=X&storepath=Y
        for sep in ("/download/", "/version="):
            pass
        # 手动抽 version / storepath
        for kv in obj.split("/"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                out[k] = v
    return out


def main():
    records = load_records(LOG)
    txs = reconstruct(records)
    print(f"共 {len(txs)} 个事务\n")
    for h, tx in txs.items():
        rb = resp_bytes(tx)
        params = parse_obj(tx["obj"] or "")
        app = params.get("appname") or params.get("storepath") or "?"
        print(f"=== {tx['ts']} handle={h} ===")
        print(f"  {tx['verb']} {tx['server']}  app={app}  ver={params.get('version','-')}")
        print(f"  resp {len(rb)}B")
        # 前 64 字节 hex+ascii
        head = rb[:64]
        print(f"  head hex: {head.hex()}")
        print(f"  head asc: {''.join(chr(b) if 32<=b<127 else '.' for b in head)!r}")
        # 5B 特判
        if len(rb) <= 8:
            print(f"  small resp: {rb!r}")
        # 看是否压缩(gzip 1f 8b / zlib 78 9c / 自定义)
        if rb[:2] == b"\x1f\x8b":
            print("  [gzip?]")
        elif rb[:1] in (b"\x78",):
            print("  [zlib?]")
        print()


if __name__ == "__main__":
    main()
