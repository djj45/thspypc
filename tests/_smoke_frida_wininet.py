#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""冒烟测试:attach 到 explorer.exe 8 秒,确认 WinINet hook 能 load + 拦到调用。

不启动同花顺。explorer 常驻且偶尔会发 WinINet 请求(图标/网络)。
如果连 explorer 都拦不到,说明 hook 写法有问题。
"""
import pathlib
import sys
import time

import frida

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOOK_JS = ROOT / "tests" / "_blockupdate_frida_hook.js"

notes = []
requests = []
ready = [False]
bodies = []
qis = []


def on_message(msg, data):
    if msg["type"] == "error":
        print("JS ERROR:", msg.get("description"))
        return
    p = msg.get("payload", {})
    t = p.get("t")
    if t == "ready":
        ready[0] = True
        print("  [ready]")
    elif t == "note":
        notes.append(p["msg"])
        print("  [note]", p["msg"])
    elif t == "request":
        requests.append(p)
        print(f"  [REQ] {p.get('verb')} {p.get('server')}:{p.get('port')}{p.get('obj')}")
    elif t == "resp_body":
        n = p.get("len", 0)
        got = len(data) if data else 0
        bodies.append((p.get("handle"), n, got, data[:32] if data else b""))
        if got:
            print(f"  [RESP_BODY] handle={p.get('handle')} len={n} got_bytes={got} head={data[:32].hex()}")
    elif t == "query_info":
        qis.append(p)
        print(f"  [QI] {p.get('infoLevel')} = {p.get('value')!r}")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "explorer.exe"
    print(f"attach {target} 8s, 验证 WinINet hook ...")
    dev = frida.get_local_device()
    pid = None
    for p in dev.enumerate_processes():
        if p.name.lower() == target.lower():
            pid = p.pid
            break
    if pid is None:
        print(f"找不到 {target}")
        sys.exit(1)
    print(f"  pid={pid}")
    session = dev.attach(pid)
    script = session.create_script(HOOK_JS.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    time.sleep(8)
    session.detach()
    print()
    print(f"ready={ready[0]} notes={len(notes)} requests={len(requests)} bodies={len(bodies)} qi={len(qis)}")
    print("hooks 确认:", notes)
    if requests:
        print("样本请求:")
        for r in requests[:3]:
            print("  ", r.get("verb"), r.get("server"), r.get("obj"))
    if bodies:
        total = sum(b[2] for b in bodies)
        print(f"响应字节: {total} bytes across {len(bodies)} chunks")
        print("  样本 head:", bodies[0][3])
    print()
    if ready[0] and notes:
        print("✓ frida + WinINet hook 链路正常")
        if bodies:
            print("✓ data 附件通道工作,响应字节可读")
    else:
        print("✗ 异常,检查 hook")


if __name__ == "__main__":
    main()
