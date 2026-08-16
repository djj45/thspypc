"""probe_check_k — 历史兼容入口；验证 login 的两个动态长度字段。

用途（playbook §13 oracle 类）：
  - 验证 raw[:2] == uint16_le(len(raw Passport64))
  - 验证 suffix == uint16_le(fixed_len + base64_len + 1)
  - 同时输出旧算法反算的 K，便于阅读历史报告

**2026-08-17 根因**：BE/C8/BA/E8 是 raw 长度的小端低字节；所谓 K 恒等于
``(len(Passport64)+1)&0xff``，不是版本或票据状态。完整离线 oracle 见
``tests/analyze_login_length_fields.py``。

如果未来出现 -1 回归，先确认两个声明长度是否与最终 payload 一致。
**不自动改代码**——避免探测错误导致静默故障。

用法：
    py tests/probe_check_k.py captures_live/login_compare.pcap
    py tests/probe_check_k.py captures_live/hexin_login_now.pcapng

依赖：scapy（py -m pip install scapy）。纯 Python，不需要 tshark/Wireshark。

⚠ 这是诊断/oracle 工具，不是生产解码器。输出供人工判断。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from scapy.all import rdpcap, TCP, IP  # noqa: E402

from thspypc.codecs.compression import normalize_8901_response  # noqa: E402

MAGIC = b"\xfd\xfd\xfd\xfd"
INIT_HEADER_LEN = 23  # build_init_query 的 23 字节头


def reassemble_stream(pkts, client_key: tuple) -> bytes:
    """按 TCP seq 重组单方向字节流（gap 用 NUL 填充）。"""
    chunks: list[tuple[int, bytes]] = []
    base_seq = None
    for p in pkts:
        if TCP not in p or IP not in p:
            continue
        if (p[IP].src, p[TCP].sport) != client_key:
            continue
        payload = bytes(p[TCP].payload)
        if not payload:
            continue
        seq = p[TCP].seq
        if base_seq is None:
            base_seq = seq
        chunks.append((seq - base_seq, payload))
    chunks.sort()
    out = bytearray()
    for off, data in chunks:
        if off > len(out):
            out.extend(b"\x00" * (off - len(out)))
        if off + len(data) > len(out):
            out.extend(data[len(out) - off :])
        else:
            out[off : off + len(data)] = data
    return bytes(out)


def split_frames(stream: bytes) -> list[tuple[int, bytes]]:
    """切 fdfdfdfd magic + 8 字节 ASCII hex 长度的帧。返回 [(flen, body)]。"""
    frames = []
    for sub in stream.split(MAGIC):
        if len(sub) < 8:
            continue
        try:
            flen = int(sub[:8], 16)
        except ValueError:
            continue
        body = sub[8 : 8 + flen] if flen <= len(sub) - 8 else sub[8:]
        frames.append((flen, body))
    return frames


def parse_login_fields(body: bytes) -> dict[str, str]:
    idx = body.find(b"Ask=login")
    if idx < 0:
        idx = body.find(b"Ask=")
    if idx < 0:
        return {}
    text = body[idx:].decode("gbk", errors="replace")
    fields: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.split("\x00")[0].strip()
    return fields


def compute_k(login_body: bytes) -> tuple[int, int, int] | None:
    """返回历史展示用的 (suffix_low, fixed_len, legacy_K)。

    fixed = Ask=login 开头到 Passport64=（不含值）的 GBK 字节数。
    prefix: 09 41 09 00 'zh_CN.GBK' <check> 09
    check 在 prefix[4+9] = prefix[13]。
    """
    prefix_idx = login_body.find(b"\x09\x41\x09\x00")
    if prefix_idx < 0:
        return None
    check_byte = login_body[prefix_idx + 4 + 9]  # 4 + len("zh_CN.GBK")=9
    fixed_start = login_body.find(b"Ask=login", prefix_idx)
    if fixed_start < 0:
        return None
    passport_idx = login_body.find(b"Passport64=", fixed_start)
    if passport_idx < 0:
        return None
    fixed_len = passport_idx + len(b"Passport64=") - fixed_start
    k = (check_byte - fixed_len) % 256
    return check_byte, fixed_len, k


def dump_init_text_fields(body: bytes) -> dict[str, str]:
    """对 init 响应帧 body，跳 23B header，解 0x0a 压缩，dump 所有 key=value。

    只保留 key/value 都是可打印文本的行（过滤 hd3.1 二进制表产生的乱码）。
    """
    if len(body) < INIT_HEADER_LEN:
        return {}
    text_body = body[INIT_HEADER_LEN:]
    if text_body.startswith(b"\x0a"):
        try:
            text_body = normalize_8901_response(text_body)
        except ValueError:
            pass
    text = text_body.decode("gbk", errors="replace")
    fields: dict[str, str] = {}
    for line in re.split(r"[\r\n\x00]", text):
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        # 过滤二进制噪声：key 必须纯 ASCII 字母数字/下划线/连字符，
        # value 必须可打印（ASCII 或可解 GBK 中文）。
        if not k or not v:
            continue
        if not re.fullmatch(r"[\x20-\x7e]+", k):
            continue
        # value 允许 ASCII + 常见标点；含控制字符或大量替换符的跳过
        if any(ord(c) < 0x20 and c not in "\t" for c in v):
            continue
        if v.count("\ufffd") > len(v) // 4:  # 超过 1/4 是替换符 = 乱码
            continue
        fields[k] = v
    return fields


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pcap", type=Path, help="hexin login 流程 pcap")
    ap.add_argument(
        "--target-k",
        type=lambda x: int(x, 0),
        default=None,
        help="历史兼容：标出 init 中等于旧 K 的字段；不填则使用反算值",
    )
    args = ap.parse_args()

    if not args.pcap.exists():
        print(f"✗ pcap 不存在: {args.pcap}", file=sys.stderr)
        return 1

    pkts = rdpcap(str(args.pcap))
    print(f"# pcap: {args.pcap}（{len(pkts)} 个包）")

    # 按 4-tuple 分流
    streams: dict[tuple, list] = {}
    for p in pkts:
        if TCP in p and IP in p and (p[TCP].dport == 8901 or p[TCP].sport == 8901):
            key = tuple(sorted([(p[IP].src, p[TCP].sport), (p[IP].dst, p[TCP].dport)]))
            streams.setdefault(key, []).append(p)

    print(f"# 8901 流数: {len(streams)}\n")

    # 对每个流验证 raw/suffix 长度，并保留旧 K 输出供历史对照。
    k_values: list[int] = []
    account_types: list[str] = []  # account_type[0] hex 字符串
    length_checks: list[bool] = []
    all_init_fields: dict[str, set[str]] = {}  # field -> set of values seen
    per_stream_init_fields: list[tuple[str, dict[str, str]]] = []

    for key, pkts_in_stream in streams.items():
        ckey = (
            (pkts_in_stream[0][IP].src, pkts_in_stream[0][TCP].sport),
            (pkts_in_stream[0][IP].dst, pkts_in_stream[0][TCP].dport),
        )
        server_ip = ckey[1][0]
        c2s = reassemble_stream(pkts_in_stream, ckey[0])
        s2c = reassemble_stream(pkts_in_stream, ckey[1])
        c2s_frames = split_frames(c2s)
        s2c_frames = split_frames(s2c)

        login_bodies = [b for _, b in c2s_frames if b"Ask=login" in b]
        if not login_bodies:
            continue

        k_result = compute_k(login_bodies[0])
        if k_result is None:
            print(f"→ {server_ip}: login 帧但无法反算 K（prefix/fixed 定位失败）")
            continue
        check_byte, fixed_len, k = k_result
        k_values.append(k)
        # 从 Passport64 解出 account_type
        atype_hex = "?"
        length_note = "length=unknown"
        fields = parse_login_fields(login_bodies[0])
        p64 = fields.get("Passport64", "")
        if p64:
            try:
                import base64
                praw = base64.b64decode(p64)
                atype_hex = praw[:5].hex()
                account_types.append(atype_hex[:2])  # 只取第一字节
                raw_declared = int.from_bytes(praw[:2], "little")
                suffix_value = int.from_bytes(login_bodies[0][13:15], "little")
                expected_suffix = fixed_len + len(p64) + 1
                length_ok = (
                    raw_declared == len(praw)
                    and suffix_value == expected_suffix
                )
                length_checks.append(length_ok)
                length_note = (
                    f"raw={len(praw)}/{raw_declared} "
                    f"suffix={suffix_value}/{expected_suffix} ok={length_ok}"
                )
            except Exception:
                pass
        has_user = "UserName" in fields
        identity = "STANDARD" if has_user else "L2/shell"
        # VerifyCode
        vc = "?"
        for fl, rbody in s2c_frames:
            if b"VerifyCode" in rbody:
                rtext = rbody.decode("gbk", errors="replace")
                vm = re.search(r"VerifyCode=(-?\d+)", rtext)
                if vm:
                    vc = vm.group(1)
                    break
        print(f"→ {server_ip}:8901  header={atype_hex}  suffix_low=0x{check_byte:02x} "
              f"legacy_K={k}  {length_note} VerifyCode={vc}  ({identity})")

        # 扫该流的 init 响应帧
        for fl, body in s2c_frames:
            if len(body) < INIT_HEADER_LEN + 10:
                continue
            # init 响应特征：header[0]==0x09 且 body 含 S-Name 或 hd3. 或大段文本
            if body[0] != 0x09:
                continue
            if not (b"S-Name" in body or b"S-Version" in body or b"hd3." in body
                    or b"Market" in body):
                continue
            init_fields = dump_init_text_fields(body)
            if init_fields:
                per_stream_init_fields.append((server_ip, init_fields))
                for fk, fv in init_fields.items():
                    all_init_fields.setdefault(fk, set()).add(fv)

    print(f"\n# === 动态长度字段汇总 ===")
    if not k_values:
        print("#  ✗ 没有可反算的 login 帧")
        return 1
    from collections import Counter
    k_counts = Counter(k_values)
    at_counts = Counter(account_types)
    consensus_k = k_counts.most_common(1)[0][0]
    consensus_at = at_counts.most_common(1)[0][0] if account_types else "?"
    print(f"#  account_type[0] 分布: {dict(at_counts)}")
    print(f"#  K 分布: {dict(k_counts)}")
    print(f"#  历史显示：header_low=0x{consensus_at.upper()} legacy_K={consensus_k}")
    if length_checks and all(length_checks):
        print(f"#  ✅ {len(length_checks)}/{len(length_checks)} 个 login 的 raw/suffix 长度声明一致")
    else:
        print(f"#  ⚠ 长度声明不一致：{sum(length_checks)}/{len(length_checks)} 通过")

    target_k = args.target_k if args.target_k is not None else consensus_k
    print(f"\n# === init 帧字段扫描（标出值 == {target_k} 的字段）===")
    if not all_init_fields:
        print("#  ⚠ 未找到 init 响应帧（可能 pcap 不含 init，或流重组失败）")
    else:
        print(f"#  共 {len(all_init_fields)} 个不同字段名，跨 {len(per_stream_init_fields)} 个 init 帧")
        matches = []
        for fk in sorted(all_init_fields):
            values = all_init_fields[fk]
            # 看 value 是否能解析为整数且 == target_k
            for v in values:
                try:
                    if int(v) == target_k:
                        matches.append((fk, v))
                except ValueError:
                    pass
        if matches:
            print(f"\n#  值 == {target_k} 的 init 字段（仅供参考，K 来源不在 init 帧）:")
            for fk, v in matches:
                print(f"#    {fk} = {v}")
        else:
            print(f"#  ✗ 没有值 == {target_k} 的 init 字段")

        # 也 dump 所有字段供人工浏览（截断长值）
        print(f"\n#  === 所有 init 字段（人工浏览）===")
        for fk in sorted(all_init_fields):
            values = sorted(all_init_fields[fk])
            display = values[0] if len(values) == 1 else f"{values[0]} (+{len(values)-1} more)"
            if len(display) > 80:
                display = display[:77] + "..."
            print(f"#    {fk} = {display}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
