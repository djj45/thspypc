#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""★关键实验：用 UserName=__manual 登录，测试能否触发 71B 推送。

核心假设（基于 cold-start 包 realtime_push_20260724_131453.pcap）：
  hexin 8 条连接里，只有 stream1（UserName=__manual / Password=__manual）
  收到 71B 逐 tick 推送；其余 stream（thsuser / 空）零推送。
  thspypc 只用普通登录（无 UserName），所以收不到推送。

本脚本：
  1. 拿一个可用 Passport64（先用 thspypc 正常登录获取，或用 connect_cached）
  2. 用 __manual 凭据开一条新 TCP 连接登录 8901
  3. 发分时订阅请求
  4. dump 收到的帧，看有没有 71B 推送

__manual login 帧格式（cold-start stream1 字节级确认）：
  prefix: 09 41 09 00 zh_CN.GBK <check> 09
  check = len(Ask=login..Passport64= 固定文本) + 1
  固定文本分隔符：UserName/Password 行用 \r\n（实测 0d 0a 0a，即值后 \r\n 再 \n），
  其余行用 \n。
"""
from __future__ import annotations
import os, sys, time, datetime, socket, struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient
from thspypc.protocol import (
    encode_frame, read_frame, build_snapshot_subscribe,
    build_subreal_query, SUBREAL_CHANNELS, SNAPSHOT_PAGEID,
    is_snapshot_push, parse_snapshot_push,
    generate_mac64, build_passport64, MARKET_PORT,
)


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip(); v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


C_VERSION_PC = "E029.60.20.0031"


def build_manual_login_body(passport64: str, mac_b64: str) -> bytes:
    """构造 __manual push 登录帧 body（字节级复刻 cold-start stream1）。

    分隔符：UserName=/Password= 行用 ``\\r\\n``（值后紧跟 0d 0a），
    其余行用 ``\\n``。check = 固定文本字节数 + 1。
    """
    # ★ 注意 __manual 格式：UserName/Password 行末是 \r\n，且其后多一个 \n
    # 实测字节：UserName=__manual\r\n\nPassword=__manual\r\n\nVerifyType=1\n
    fixed = (
        f"Ask=login\n"
        f"C-Version={C_VERSION_PC}\n"
        f"UserName=__manual\r\n\n"      # ★ \r\n + \n
        f"Password=__manual\r\n\n"      # ★ \r\n + \n
        f"VerifyType=1\n"
        f"Mac64={mac_b64}\n"
        f"C-SupportPushVer=1.0\n"
        f"C-SupReqDataVer=hq6.0\n"
        f"C-SupPushDataVer=hq6.0\n"
        f"Passport64="
    ).encode("gbk")
    check = (len(fixed) + 1) & 0xFF
    prefix = b"\x09\x41\x09\x00" + b"zh_CN.GBK" + bytes([check]) + b"\x09"
    return prefix + fixed + passport64.encode("ascii")


def build_manual_login_body_v2(passport64: str, mac_b64: str) -> bytes:
    """备用：纯 \\n 分隔（和 thsuser 一样，只是把凭据换成 __manual）。"""
    fixed = (
        f"Ask=login\n"
        f"C-Version={C_VERSION_PC}\n"
        f"UserName=__manual\n"
        f"Password=__manual\n"
        f"VerifyType=1\n"
        f"Mac64={mac_b64}\n"
        f"C-SupportPushVer=1.0\n"
        f"C-SupReqDataVer=hq6.0\n"
        f"C-SupPushDataVer=hq6.0\n"
        f"Passport64="
    ).encode("gbk")
    check = (len(fixed) + 1) & 0xFF
    prefix = b"\x09\x41\x09\x00" + b"zh_CN.GBK" + bytes([check]) + b"\x09"
    return prefix + fixed + passport64.encode("ascii")


def build_dual_subframe_trigger(code: str, market: int = 17,
                                 datatype=None, seq2: int = 0x0071) -> bytes:
    """★抓包真值双子帧触发请求（cold-start t=30.155s 字节级复刻）。

    子帧1（注册到 pageid=4214 推送通道）：
        cmd 0x09 + 22B头 + CodeList=<mk>(<code>,);\\r\\npageid=4214\\r\\n
        头：[1:5]=00 16 00 00, [5:7]=0000（seq低=0,高=0）,
             [7:11]=12 00 02 00（子帧0x0002）, [11:13]=02 00（★注册标记）
    子帧2（分时数据查询）：
        cmd 0x09 + 22B头 + CodeList + DataType + DateTime + LackTime + pageid
        头：[1:5]=00 16 00 00, [5:7]=seq2 LE16（高字节=0x00）,
             [7:11]=12 00 09 00（子帧0x0009）, [11:13]=00 01（★普通查询标记）

    两个子帧拼在一个 body 里，外层套一层 fdfdfdfd magic（encode_frame）。
    """
    import struct as _st
    if datatype is None:
        datatype = [10, 24, 30, 69, 70, 127]
    # 子帧1：注册（仅 CodeList + pageid）
    text1 = f"CodeList={market}({code},);\r\npageid=4214\r\n".encode("gbk")
    sub1 = bytearray(23)
    sub1[0] = 0x09
    sub1[1:5] = b"\x00\x16\x00\x00"
    # [5:7] = 00 00 (seq=0)
    sub1[7:11] = b"\x12\x00\x02\x00"   # 子帧 0x0002
    sub1[11] = 0x02; sub1[12] = 0x00   # byte11-12 = 02 00
    _st.pack_into("<I", sub1, 19, len(text1))
    # 子帧2：查询
    dt_str = ",".join(str(d) for d in datatype) + ","
    text2 = (
        f"CodeList={market}({code},);\r\nDataType={dt_str}\r\n"
        f"DateTime=0(0-0)\r\nLackTime=0,0,0,0,0,0,0,0\r\npageid=4214\r\n"
    ).encode("gbk")
    sub2 = bytearray(23)
    sub2[0] = 0x09
    sub2[1:5] = b"\x00\x16\x00\x00"
    _st.pack_into("<H", sub2, 5, seq2 & 0x00FF)   # seq 高字节 0x00
    sub2[7:11] = b"\x12\x00\x09\x00"              # 子帧 0x0009
    sub2[11] = 0x00; sub2[12] = 0x01              # byte11-12 = 00 01
    _st.pack_into("<I", sub2, 19, len(text2))
    body = bytes(sub1) + text1 + bytes(sub2) + text2
    return encode_frame(body)


def main():
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    code = "603118"
    for a in sys.argv[1:]:
        if a.isdigit() and len(a) == 6:
            code = a
    market = 17 if code.startswith("6") else 33

    # 选 login body 版本：v1（\r\n 分隔，字节级复刻）默认
    use_v2 = "--v2" in sys.argv

    print(f"【步骤1】正常登录获取 Passport64（thspypc 普通登录）...")
    client = THSClient(username=username, password=password, imei=imei,
                       enable_heartbeat=False)
    try:
        r = client.connect()
        if not r.success:
            print(f"✗ 普通登录失败: {r.error} / {r.detail}")
            return 1
        print(f"✓ 普通登录成功 {r.server}")
        passport64 = build_passport64(client._auth)
        mac64 = client.mac64
        host = client._connected_ip
        print(f"  host={host} passport64[:40]={passport64[:40]}... mac64={mac64[:24]}...")
        # 保留普通登录的 socket 给后面查询用？不，我们另开 __manual 连接
        client.disconnect()
    except Exception as e:
        print(f"✗ 异常: {e}")
        import traceback; traceback.print_exc()
        return 1
    finally:
        try: client.disconnect()
        except Exception: pass

    if not passport64:
        print("✗ 没拿到 passport64，退出")
        return 1

    v_label = "v2 纯LF" if use_v2 else "v1 CRLF字节级"
    print(f"\n【步骤2】用 __manual 凭据开新连接登录（{v_label}）...")
    login_body = (build_manual_login_body_v2 if use_v2 else build_manual_login_body)(passport64, mac64)
    print(f"  login body 固定文本 check byte = 0x{login_body[13]:02x}")

    from thspypc.protocol import MARKET_PORT as _MP  # noqa
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.sendall(encode_frame(login_body) + b"\n")
    sock.settimeout(8.0)
    try:
        resp = read_frame(sock)
    except Exception as e:
        print(f"✗ 读 login 响应失败: {e}")
        sock.close(); return 1
    # 解析
    txt = resp.decode("gbk", "replace")
    print(f"  __manual login 响应 ({len(resp)}B):")
    vc = ""
    if "Reply=" in txt:
        for line in txt.replace("\r\n", "\n").split("\n"):
            if "=" in line:
                print(f"    {line[:70]}")
                if line.startswith("VerifyCode="):
                    vc = line.split("=", 1)[1]
    else:
        print(f"    head: {resp[:40].hex(' ')}")
        print(f"    ascii: {resp[:80].decode('gbk','replace')!r}")

    if vc != "0":
        print(f"\n✗ __manual 登录失败 VerifyCode={vc!r}")
        print("  （说明 __manual 凭据不被接受，或需要其他条件）")
        sock.close()
        return 1
    print(f"✓ __manual 登录成功！VerifyCode=0")

    # 步骤3：发订阅 + dump
    use_single = "--single" in sys.argv
    trig_kind = "single(当前thspypc: seq0x10/0201)" if use_single else "dual(抓包真值: 0x0002注册+0x0009查询)"
    print(f"\n【步骤3】发 subreal×5 + 4214 分时订阅（code={code} market={market}）触发格式={trig_kind}")
    print(f"        dump {30}s 帧流...")
    with open(os.path.join(os.path.dirname(__file__), "..", "captures_live", "_manual_test_out.txt"), "w", encoding="utf-8") as fout:
        def log(s):
            print(s); fout.write(s + "\n"); fout.flush()
        # subreal×5 前置
        for ch in SUBREAL_CHANNELS:
            body = build_subreal_query(0x7FFFFFFF, channel=ch, action="change", pageid=SNAPSHOT_PAGEID)
            sock.sendall(encode_frame(body) + b"\n")
        log("  已发 subreal×5 前置")
        if use_single:
            # 当前 thspypc 格式：单子帧 seq高字节0x10 + byte11-12=02 01
            frame = build_snapshot_subscribe(code, market=market, seq=0x0086)
            sock.sendall(frame + b"\n")
            log("  已发 4214 单子帧（seq高字节0x10, byte11-12=02 01）")
        else:
            # ★抓包真值 t=30.155s：双子帧拼接（子帧1 注册 0x0002 + 子帧2 查询 0x0009）
            frame = build_dual_subframe_trigger(code, market=market)
            sock.sendall(frame + b"\n")
            log("  已发 4214 双子帧（子帧1 0x0002注册 byte11-12=02 00 + 子帧2 0x0009查询 byte11-12=00 01）")

        sock.settimeout(2.0)
        t0 = time.time()
        n = 0; snap_n = 0
        while time.time() - t0 < 30:
            try:
                body = read_frame(sock)
            except socket.timeout:
                continue
            except (OSError, ValueError) as e:
                log(f"  [read err] {e}")
                break
            n += 1
            if is_snapshot_push(body):
                snap_n += 1
                rec = parse_snapshot_push(body)
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                log(f"  [{ts}] #{n} ★SNAP {len(body)}B: {rec}")
                continue
            if n <= 5:
                head = body[:40].hex(' ')
                asc = body[:60].decode('gbk', 'replace').replace('\n', '|').replace('\r', '')[:60]
                log(f"  #{n} {len(body)}B: {head}")
                if asc.strip():
                    log(f"        ascii: {asc!r}")
        log(f"\n【汇总】30s 内收到 {n} 帧，其中 71B 快照 {snap_n} 个")
        if snap_n > 0:
            log("✓✓✓ __manual 登录成功触发推送！假设验证通过！")
        elif n == 0:
            log("✗ 零响应。__manual 登录但订阅请求未触发。")
        else:
            log("⚠ 有响应但无 71B 推送。需进一步研究订阅请求格式或预热序列。")

    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
