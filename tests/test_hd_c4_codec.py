"""0xc4 金额表编解码单测（fixture 来自 2026-08-18 活网抓包）。

- hd3.1 魔数 + dc 高 8 位 0x01 + 64B 前导 + BitRLE（大批量 ≥3 行）
- hd1.0 魔数 + dc 高 8 位 0x01 + 60B 前导 + 明文（小批量 2 行，末行可缺 1 字节）
- 字段 fmt 0x79/0x7B 与 0x70 同为 THS 定点浮点（dt250 主力净额元、
  dt248 DDE 主力亿、dt202 总市值元，活网与 /api/dde_rank 交叉验证）
"""
from __future__ import annotations

import base64

from thspypc.codecs.hd import parse_hd1_response, parse_hd3_response
from thspypc.features.quote_protocol import derive_list_quote_fields

# captures_live/c4/c4_s0_301_1493B.bin：沪市 14 行（688077 等），盘后快照
HD3_C4_FRAME = base64.b64decode(
    "CQAW/w9UERIACQBWAQABEAAAALsFAABOAAAATWFya2V0VGltZT0xNig1OTQwMCk7MjcyKDYwMTI3"
    "KTs1MjgoNTk0MDApOzE0NCg1ODM1NSk7NDAwKDU4MzU1KTs2NTYoNTk4NTUpOw0KaGQzLjEADgAA"
    "AcQAiwAeAAUgAAcHcAAEMXAABA1wAARGcAAEG3AABH8gABAwcAAEDDAABEVwAAQhcAAEGXAABApw"
    "AAQRcAAEGHAABB9wAAQJcAAEHnAABAhwAATIeQAEyHkABH57AAT6ewAEynkABPh7AASDewAEBnAA"
    "BC1wAARCcAAEV2QBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAeAAAA"
    "CQA2AAkAAAAAAAAAAAAAAKUEAAAAAAea4j/gD/g6A2c//oAiH/AH2f4Pw+APHvwBzg/e/AHKD4gG"
    "IYLDtsFRDx9TFFoQo2wCD6KhzzeVDgPZJA/IoEhapACMp06pdVmZv6Ms18kwYUr9CYX+3OHbyhgW"
    "UReIGgIQzwFt8DiQK+AFm/gAGwUYcuV49rs+oAKoSUgCLkRALyACFAhEBQL8Ckt4AKBsuM+OPIOK"
    "PwulHViwTEIA4LS3heTSn95TepZ5HCummhIJ+Ethbs+m0pDPAcAAIAjpeAcRi/azkQxWOOTP13Ib"
    "phpiBBwLkwi/28MhAYAI/QXw++AFKGl4BjRnT4f4qKDH6gSAUwZTmBGBBkBBS7MC+A9/qeAHxfBE"
    "A3/lf8A0H3/lf8A+H09/wB/kgKAJiJAkkSGQAhAgCN8IgMIRBClASAqkkX+gAaR9/CcgCAD9uCvG"
    "S1BKaDqjgQtm8cTkBBWQbkrJ6vwVjyzVM4iTAvcD8PuMEGgAAzUm/TFNwp3k4/FoM9YZHreGBBBA"
    "DBA/AoIPGKVEMZkAJW7lMPj1VWw30gsDYWcKU8PICCIBSAqAgoBYGJ+EgAsg6ryoOv5JSHlIMqoA"
    "pUl9Icc9JMRq1jzPvXSOtGPVF4gBAhBZAe3woMMLtoTLCQsfAGPAJcrcPlUpCghwg3jLTRREjFhs"
    "M5IcNwxA7g0geQBoKu9NRmmK0qqUSXkjRwI9JMRq1jzPvXSOtNUXiBoBAhDPAW3wyDgAECFjYGFd"
    "zIHzJ9FQIERDFIDB1BFAARNAwBD5DRiAwEhLxi2cT81tVAB9HwGk1Um1LWo+jP7+YdPKSBgWUReI"
    "1gIQewFu8KCQgqSwcD7ICQAxRCBoI1ocRcc1IEZaljTHGL1wDpSVF4AB1gIQegHzkPdQMIh9mBqs"
    "AA1Q7A6y28SBbRfGWVSzKsESrEr4FY081TeISQITBAHb8EAgJ5YKQaHdQRUQA3lKQ5gYgncGUqI4"
    "QG2QgcuDDbeYM/oNH2O/awBEVGjwDfgHhQATaxMPoi5ZbIg3F/RMA9W9MH465tixdpC9ZDngBQQB"
    "/gXQ8BAqlAIESA2RQyPEKhVGuEPNEJBGGRBpECGEQAkSJtQ3xAwZQCAU6gIw9f4A5tjKhm8a7AeY"
    "8NkVpQEAhfP5GcbV1Cx/8LCfYQUOKwBl88XSOVHsuWFQpPCyzNWcNFGkCMkuQAgkvC+MCbSC9CIA"
    "tg22SW58uj6NmarrWrAAKHXP21yE1UMf45fRO03h1BmMkuv7mOWVKA4CcOCUByVWAMlnptXptiNC"
    "xG3PXdFqV2w0SbY+AiQxTwFBgNoGpAja8ADT8EC8reurTuzaoKpoyFpuAupJlgHinj25zxClGmIC"
    "fxQJbvCgcAhaJChNbRMAkdTMu0MFmf2kLK3pDevYaA2biAgGVReIAUAC/QPwoCk45ruhJYikACum"
    "xls1rherKtmTMBo7lUsAThh6ApKkREZLjQymMMJ7Ak0PciAQLjkQ/906wFYDwD0P/C4/8A/8A1gP"
    "/ANQP/AP/APAP/AP4fwDwD/wD/wDw8A/8A/8A4fAP/AP/AMOwD/wD/wDHMA/8A/8AzjAP/AP/APA"
    "P3HwD/wDwD/wD2A="
)

HD1_C4_FRAME = base64.b64decode(
    "CQAW/w8lABIACQAAAQABEAAAABICAAA4AAAATWFya2V0VGltZT0zMig1Nzc5OCk7Mjg4KDU5NDYw"
    "KTs1NDQoNTk0NjApOzgwMCg1Nzc5OCk7DQpoZDEuMAACAAABxACLAB4ABSAABwdwAAQxcAAEDXAA"
    "BEZwAAQbcAAEfyAAEDBwAAQMMAAERXAABCFwAAQZcAAECnAABBFwAAQYcAAEH3AABAlwAAQecAAE"
    "CHAABMh5AATIeQAEfnsABPp7AATKeQAE+HsABIN7AAQGcAAELXAABEJwAARXZAEIAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAB4AAAAJADYACQAAAAAAAAAAAAAAITAwMDcy"
    "NeTtAMCwBAAAdcfuIazVAMD89k0ARTAgICAgICAAAAAAAAAAAJsAALARAAAAVAUBwMpCswCMqAEB"
    "vPwAwDv5FQFY/ADAfoaHAOTtAMC8/ADAIP0AwACHBMgkZgHA/1oFwOIjqRXAt21BbRAAwMtEAMCA"
    "7QDA51NzJP//////pjEB0AcAsCEwMDA2MjA0hQDAyAAAACFoIRL8bADAKPAUAEUwICAgICAgAAAA"
    "AAAAAAAAAAAAEQAAADSFAMAAAAAAtMY5AzSFAMCcQBcCNIUAwAAAAABMgQDAAAAAgDSFAMBAQg/A"
    "3ioBwAAAAIB5Gd0SaYYxMdp1AMBv1QDAGHkAwH2YFyH//////6YxAeAuAA=="
)


def test_hd3_c4_bitrle_frame_decodes():
    rows = parse_hd3_response(HD3_C4_FRAME)
    assert len(rows) == 14
    first = rows[0]
    assert first["code"] == "688077"
    # fmt 0x70 字段（价格类）
    assert first["dt10"] == 32.26
    assert first["dt6"] == 27.85
    # fmt 0x7B：dt250 主力净额（元），负值 = 主力净流出（盘后快照）
    assert first["dt250"] == -11248840.2
    # fmt 0x79：dt202 总市值（元）≈ 36.9 亿
    assert first["dt202"] == 3693076500.0
    # 重复 dt200 字段带 #2 后缀，不互相覆盖
    assert "dt200" in first and "dt200#2" in first


def test_hd1_c4_plain_frame_decodes_with_short_tail():
    rows = parse_hd1_response(HD1_C4_FRAME)
    assert len(rows) == 2
    assert rows[0]["code"] == "000725"
    assert rows[1]["code"] == "000620"
    assert rows[0]["dt250"] == 949708500.0
    assert rows[1]["dt250"] == 480444090.0
    assert rows[0]["dt248"] == 0.4205


def test_derive_passes_money_fields_and_amount_fallback():
    record = {
        "code": "600519",
        "dt6": 1293.09,
        "dt7": 1295.0,
        "dt10": 1297.99,
        "dt13": 3_861_510_000,  # 成交量（股），无 dt19
        "dt17": 23_500,
        "dt48": -0.017,
        "dt250": -142988470.0,
        "dt248": -0.0089,
        "dt202": 1622593400000.0,
    }
    row = derive_list_quote_fields(record)
    assert row["main_inflow"] == -142988470.0
    assert row["dde_main"] == -0.0089
    assert row["market_cap"] == 1622593400000.0
    # dt19 缺失时成交额 = dt13 × dt10
    assert row["amount"] == 3_861_510_000 * 1297.99
    assert row["chg_pct"] == 0.38
