# 登录协议完整逆向（2026-08-10 更新）

本文档记录 thspypc 与 hexin 客户端 8901/9601 登录协议的完整字节级对比结论。
**取代 HANDOFF.md §2（2026-07-23 版）** 中已被推翻的旧分析。

## 旧分析为什么过时

2026-07-23 的旧分析基于以下假设，后来被 2026-08-10 的 hexin 抓包**全部推翻**：

| 旧假设（2026-07-23） | 实际情况（2026-08-10 抓包） |
|---|---|
| hexin 发送 20 字段（1130 字符）的短 passport | hexin 发送 **44 字段（2316 字符）** 的长 passport |
| thspypc 发 43 字段（2304 字符），靠保留 sk/sv 补偿 | thspypc 和 hexin 都是 **44 字段**，字段值完全一致 |
| check 字节 = `(len+1)&0xFF` | check 字节 = **`(len+13)&0xFF`** |
| account_type = `BE 06 06 80 00` | account_type = **`C8 06 06 80 00`** |
| passport 尾部 = 空格 `0x20` | passport 尾部 = **NUL `0x00`** |

## 为什么旧代码一直"能登"，到 8/10 突然不行了

**代码没变，是服务端收紧了校验。**

thspypc 的登录帧（0xBE / +1 / STANDARD 带 UserName）和 hexin 真实帧
（0xC8 / +13 / 无 UserName）从来就不一样，但**服务器以前宽容**，不校验这些差异，
所以旧代码一直能用。证据：
- 8/6 逐笔回放（commit 5d92483）、8/7 超级盘口（commit 39df7f8）、8/9 委托队列
  （commit bda8828）都走 shlv2/szlv2 + `LoginIdentity.STANDARD`（带 thsuser），
  活网验证全部通过——**L2 登录当时是成功的**。
- 8/10 起，同样的旧代码在 shlv2/szlv2/main 上全部 `VerifyCode=-1`。

8/9 周日到 8/10 周一，同花顺服务端做了更新，从宽容校验切换成严格校验。
hexin 客户端一直发的是正确值（0xC8 / +13 / 无 UserName），不受影响；
thspypc 发的是旧值，之前服务器宽容能过，收紧后被拒。

**这次修复的本质**：把 thspypc 的帧对齐到 hexin 真实值，使其不再依赖
服务器的宽容校验。修复后无论服务器宽不宽容都能登。

> ⚠️ **教训**：不能用"旧代码能登"反推"代码是对的"。服务器的宽容校验会掩盖
> 帧内容差异。只有和 hexin 真实帧做**字节级对比**才能确认帧是否正确。
> 2026-07-23 的旧逆向就是吃了这个亏——没抓 hexin 真实帧，从自己帧反推公式，
> 碰巧 ifindhq 宽容能过，就以为对了。

## 2026-08-10 完整字节级对比

### 抓包方法

```
py tests/capture_login_compare.py   # 抓 hexin 冷启动 8901 login 序列
```

hexin 抓包确认：**8 个 login 帧全部 VerifyCode=0**（覆盖 MAIN + shlv2 + szlv2 + fu4）。

### 登录帧完整结构

```
┌─ 帧封装 ─────────────────────────────────────────────────┐
│ fd fd fd fd  <8字节大端长度>  <login body>  \n           │
└──────────────────────────────────────────────────────────┘

login body 结构：
┌─ prefix (15B) ──────────────────────────────────────────┐
│ 09 41 09 00  zh_CN.GBK  <check>  09                     │
│ \t  A  \t \0 ←9字节─→ ↑1B ↑1B                           │
└─────────────────────────────────────────────────────────┘
┌─ fixed 文本 ────────────────────────────────────────────┐
│ Ask=login\nC-Version=...\n[UserName=...\n][Password=...\n│
│ ]VerifyType=1\nMac64=...\nC-SupportPushVer=1.0\n         │
│ C-SupReqDataVer=hq6.0\nC-SupPushDataVer=hq6.0\n          │
│ Passport64=                                              │
└──────────────────────────────────────────────────────────┘
┌─ Passport64 值（base64）─────────────────────────────────┐
│ <2316/2320 字符>                                         │
└──────────────────────────────────────────────────────────┘
```

### check 字节公式

```
check = (len(fixed) + 13) & 0xFF
```

其中 `fixed` = `Ask=login` 开头到 `Passport64=`（不含值）的 GBK 编码字节数。

实测验证（2026-08-10 hexin 8 帧抓包）：

| 身份 | fixed 长度 | check 字节 | 公式验证 |
|---|---|---|---|
| MAIN（带 UserName）| 203B | `0xD8` | `(203+13)&0xFF = 216 = 0xD8` ✓ |
| L2/fu4（无 UserName）| 169B | `0xB6` | `(169+13)&0xFF = 182 = 0xB6` ✓ |

> **旧公式 `(len+1)&0xFF` 是错的。** 它在 ifindhq（宽松）上能过，但 main/shlv2/szlv2/fu4
> 等严格服务器返回 -1 或直接 FIN。

## 五处协议修正（全部 2026-08-10 确认并修复）

### 修正 1：account_type[0] 0xBE → 0xC8

**文件**：`src/thspypc/features/auth_protocol.py:42`（PC_LEVEL2_LOGIN_PROFILE）

hexin 抓包 8/8 帧（MAIN + L2 + fu4）的 head128[:5] 全是 `C8 06 06 80 00`。
thspypc 旧值 `BE 06 06 80 00` 被 ifindhq 容忍，被 main/shlv2/szlv2/fu4 拒（-1）。

PC_STANDARD（`E8 04 06 80 00`）无抓包证据，**不改**。

### 修正 2：passport 尾部字节 0x20 → 0x00

**文件**：`src/thspypc/features/auth_protocol.py:151`（build_passport64）

```python
# 改前
payload = head128 + prefix_5b + b"\r\n".join(fields) + b"\r\n "
# 改后
payload = head128 + prefix_5b + b"\r\n".join(fields) + b"\r\n\x00"
```

hexin passport 尾部 = `...\r\n\x00`（字段 join 后 trailing CRLF + NUL）。
旧值 `\r\n `（CRLF + 空格）差 1 字节。

### 修正 3：check 字节公式 +1 → +13

**文件**：`src/thspypc/features/auth_protocol.py:220,259`（BOARD 分支 + 通用 fallback）

两处 `(len(fixed) + 1) & 0xFF` → `(len(fixed) + 13) & 0xFF`。

- **通用 fallback**（:259）：影响 MAIN(L2 STANDARD)、SH_L2/SZ_L2(L2)、REALORDER、STATSCALC、
  BOARD_CONSTITUENT。
- **BOARD 分支**（:220）：影响 fu4 板块通道。

### 修正 4：新增 LoginIdentity.L2（无 UserName）

**文件**：`src/thspypc/features/auth_protocol.py:16`（枚举）、`:181-197`（build_login_body 分支）、
`src/thspypc/_client/connection_primitives.py:738`（_try_open_manual_sock）

hexin L2 帧（shlv2/szlv2）= **无 UserName/Password 的 7 字段壳**：
`Ask / C-Version / VerifyType / Mac64 / C-SupportPushVer / C-SupReqDataVer /
C-SupPushDataVer / Passport64`。

旧代码用 STANDARD（带 `UserName=thsuser`）登 L2，被严格服务器拒。
新增 `LoginIdentity.L2` 生成正确的无 UserName 壳。

> 注意：MAIN 帧仍然带 `UserName=thsuser`（hexin 抓包确认 MAIN 帧2/3 带 UserName）。
> 不是所有登录都去掉 UserName——只有 L2 push 通道。

### 修正 5：BOARD(fu4) check 字节 +1 → +13

**文件**：`src/thspypc/features/auth_protocol.py:220`

fu4 抓包确认 check = `0xB6`（= `(169+13)&0xFF`），旧值 `0xAA`（= `(169+1)&0xFF`）。
`test_board_channel.py:65` 断言同步更新 `aa 09` → `b6 09`。

## 每个服务器角色的登录身份

| 角色 | 服务器 | LoginIdentity | UserName | check 公式 | 验证 |
|---|---|---|---|---|---|
| MAIN | main/ifindhq:8901 | STANDARD | thsuser | +13 | ✅ |
| SH_L2 | shlv2:8901 | **L2** | 无 | +13 | ✅ |
| SZ_L2 | szlv2:8901 | **L2** | 无 | +13 | ✅ |
| REALORDER | 106.14.65.90:9601 | STANDARD | thsuser | +13 | ✅ |
| BOARD | fu4:8901 | BOARD | 无(L2)/__manual(普通) | +13 | ✅ |
| BOARD_CONST_SH | shlv2/main:8901 | STANDARD | thsuser | +13 | ✅ |
| BOARD_CONST_SZ | szlv2:8901 | MANUAL | __manual | +13 | ✅ |
| BOARD_STATS | 8.132.233.77:9601 | STANDARD | thsuser | +13 | ✅ |

**活网验证**：`tests/verify_all_logins.py` → 7/7 角色全部 VerifyCode=0。

## 验证工具

| 脚本 | 用途 |
|---|---|
| `tests/capture_login_compare.py` | 抓 hexin 8901 login 序列，4 维度对比 |
| `tests/verify_all_logins.py` | 全 7 类服务器登录冒烟（单 client 逐角色） |
| `tests/verify_order_details_online.py` | L2 4214 挂单/撤单明细端到端验证 |
| `tests/compare_passport64_values.py` | 逐字段对比 thspypc vs hexin passport |

## 关键结论

1. **字段过滤是对的**：`PASSPORT_DROP_FIELDS` 只丢 10 个路由字段，保留 44 字段（含 sk/sv），
   和 hexin 完全一致。**不需要复刻 hexin 的字段过滤**——thspypc 已经对了。
2. **check 公式统一是 `+13`**：所有身份（STANDARD/MANUAL/BOARD/L2）都用 `(len+13)&0xFF`。
3. **严格 vs 宽松服务器**：ifindhq 不校验 account_type/check（宽松）；main/shlv2/szlv2/fu4
   严格校验。修复前 thspypc 只能登 ifindhq；修复后全部可登。
4. **sk/sv 必须保留**：thspypc 的 head128（移植自 thspy Mac 版 `signature_to_nibbles`）没有
   把 sk/sv 编码进 signature，所以必须保留 sk/sv 明文字段。这点旧分析是对的。
