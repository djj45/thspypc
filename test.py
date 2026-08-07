"""干净的自包含分时查询脚本（不经过 client.py 的复杂连接管理）。

复刻独立 test.py 验证过的成功路径：
  connect → disconnect → __manual 登录 → init(MarketCode=32) → 4214 订阅 → L2 分时查询
"""
import sys; sys.path.insert(0,'src')
from thspypc import THSClient
from thspypc.protocol import (
    build_passport64, build_manual_login_body, build_snapshot_subscribe,
    build_init_query, build_timeline_l2_query, encode_frame, read_frame,
    parse_kline_hd3_response, parse_timeline_l2_response, MARKET_PORT,
    resolve_l2_hosts,
)
import os, socket, re, time

for line in open('.env', encoding='utf-8'):
    line = line.strip()
    if '=' in line and not line.startswith('#'):
        k, _, v = line.partition('=')
        os.environ.setdefault(k.strip(), v.strip().strip('"'))

code = sys.argv[1] if len(sys.argv) > 1 else "000938"
market = 17 if code.startswith("6") else 33

# 1. 普通登录拿 Passport64
c = THSClient(os.environ['THS_USERNAME'], os.environ['THS_PASSWORD'],
              imei=os.environ.get('THS_IMEI', '') or None, enable_heartbeat=False)
r = c.connect()
if not r.success:
    print(f"✗ 登录失败: {r.error}"); sys.exit(1)
ip = c._connected_ip
passport64 = build_passport64(c._auth)
mac64 = c.mac64
main_ip = ip  # 主连接用的 IP（__manual 要避开它，避免同 IP 会话冲突）
# ★ 优先用 L2 服务器 IP（shlv2/szlv2 域名解析），且避开主连接 IP
l2_ips = resolve_l2_hosts(c._auth.get("passport_bytes", b""))
if l2_ips:
    # 排除主连接 IP（避免同 IP 会话冲突 VC=-1）
    avail = [x for x in l2_ips if x != main_ip]
    if not avail:
        avail = l2_ips  # 全部被排除就只能用这些
    import random
    ip = random.choice(avail)
    print(f"① 主连接 {main_ip}，L2 IP 池 {len(l2_ips)} 个，__manual 选用 {ip}")
else:
    print(f"① 无 L2 IP，用主连接 IP {ip}")
c.disconnect()
print(f"   Passport64 已获取，主连接已断开")

# 2. __manual 登录开新连接
sock = socket.create_connection((ip, MARKET_PORT), timeout=15)
sock.sendall(encode_frame(build_manual_login_body(passport64, mac64)) + b"\n")
sock.settimeout(8)
resp = read_frame(sock)
vc = ""
for line in resp.decode("gbk", "replace").replace("\r\n", "\n").split("\n"):
    if line.startswith("VerifyCode="):
        vc = line.split("=", 1)[1]
if vc != "0":
    print(f"✗ __manual 登录失败 VC={vc}"); sys.exit(1)
print(f"② __manual 登录成功")

# 3. init(MarketCode=32) 排空完整响应
sock.sendall(build_init_query(market_code="32;") + b"\n")
n_bytes = 0
init_frames = []
for _ in range(30):
    sock.settimeout(3.0)
    try:
        b = read_frame(sock)
        n_bytes += len(b)
        init_frames.append(b)
    except (socket.timeout, OSError, ValueError):
        break
print(f"③ init(MarketCode=32) 排空 {n_bytes}B ({len(init_frames)}帧)")
for j, f in enumerate(init_frames[:3]):
    print(f"  init帧#{j}: {f[:40].hex(' ')} | {f[:40].decode('gbk','replace')[:40]!r}")
if n_bytes < 5000:
    print(f"  ⚠ init 响应过小（{n_bytes}B），此 IP 可能不支持 __manual 行情通道")

# 4. 4214 订阅
sock.sendall(build_snapshot_subscribe(code, market=market, seq=0) + b"\n")
sock.settimeout(5)
cls = None
for _ in range(5):
    try:
        body = read_frame(sock)
    except (socket.timeout, OSError, ValueError):
        break
    m = re.search(rb"CodeListSize=(\d+)", body)
    if m:
        cls = int(m.group(1))
        break
print(f"④ 4214 订阅 CodeListSize={cls}")
if not cls or cls < 1:
    print("✗ 注册失败"); sock.close(); sys.exit(1)

# 5. L2 分时查询 (DateTime=8192)
extra = "32(399002,);" if market == 33 else "16(1A0002,);"
sock.sendall(build_timeline_l2_query(code, market=market, extra_codelist=extra) + b"\n")
sock.settimeout(10)
all_recs = []
got_data = False
for i in range(20):
    try:
        body = read_frame(sock)
    except socket.timeout:
        print(f"  #{i} timeout"); break
    except (OSError, ValueError) as e:
        print(f"  #{i} err: {e}"); break
    # 打印每个响应帧摘要
    hd_tag = "hd3.1" if b"hd3.1\x00" in body else ("hd1.0" if b"hd1.0\x00" in body else "")
    txt_preview = body[:60].decode("gbk","replace").replace("\n","|").replace("\r","")[:60]
    print(f"  #{i} [{len(body)}B] {hd_tag} {txt_preview!r}")
    if hd_tag or len(body) > 1000:
        # 详细 dump 大帧结构
        idx = body.find(b"hd3.1")
        if idx < 0:
            idx = body.find(b"hd1.0")
        if idx >= 0:
            base = idx + 6  # hd3.1\0 之后
            print(f"    hd标记@{idx}, base={base}")
            if base + 10 <= len(body):
                import struct
                dc = struct.unpack("<I", body[base:base+4])[0]
                flag = struct.unpack("<H", body[base+4:base+6])[0]
                hs = struct.unpack("<H", body[base+6:base+8])[0]
                fc = struct.unpack("<H", body[base+8:base+10])[0]
                print(f"    dc={dc}(0x{dc:x}) flag=0x{flag:04x} hs={hs} fc={fc}")
                # 字段表
                ft_off = base + 10
                if fc > 0 and fc < 50:
                    ft = body[ft_off:ft_off+fc*4]
                    fields = [(ft[j*4], ft[j*4+1], ft[j*4+3]) for j in range(fc)]
                    print(f"    字段表({fc}): {[(d,w) for d,_,w in fields[:15]]}...")
                # 壳头区域：字段表后到 BitRLE 头之间
                shell_off = ft_off + fc * 4
                shell = body[shell_off:shell_off+60]
                print(f"    壳头@{shell_off}: {shell.hex(' ')}")
                # 在壳头后 0-80B 范围搜 BitRLE 头（尝试多种 expect 值）
                expect = dc * hs
                half_dc = (dc // 2) * hs  # 单票 dc
                for label, exp in [("dc*hs", expect), ("dc/2*hs", half_dc),
                                   ("dc*hs/2", expect//2)]:
                    for shell_len in range(20, 80):
                        pos = shell_off + shell_len
                        if pos + 4 <= len(body):
                            bh = struct.unpack(">I", body[pos:pos+4])[0]
                            if bh == exp:
                                print(f"    ★ BitRLE头[{label}={exp}]匹配! 壳头后偏移={shell_len} (绝对pos={pos})")
                                break
                    else:
                        continue
                    break
    if hd_tag:
        recs = parse_timeline_l2_response(body)
        if not recs:
            recs = parse_kline_hd3_response(body)  # 回退到 K线解析器
        if recs:
            all_recs.extend(recs)
            got_data = True
            sock.settimeout(2.0)
            continue
        else:
            print(f"    解析返回空")
    if got_data:
        break

print(f"⑤ 收到 {len(all_recs)} 根分时")
if all_recs:
    # 打印第一根的所有字段，确认有哪些数据
    print(f"  首根全部字段: {all_recs[0]}")
    print()
    for r in all_recs[:3]:
        print(f"  bar={r.get('bar_index','')} 现价={r.get('dt10','?')} "
              f"量={r.get('dt13','?')} 额={r.get('dt19','?')} 均价={r.get('dt14','?')}")
    print("  ...")
    for r in all_recs[-2:]:
        print(f"  bar={r.get('bar_index','')} 现价={r.get('dt10','?')} "
              f"量={r.get('dt13','?')} 额={r.get('dt19','?')} 均价={r.get('dt14','?')}")
sock.close()
