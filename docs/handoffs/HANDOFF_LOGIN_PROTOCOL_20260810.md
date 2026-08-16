# 登录协议完整逆向（2026-08-17 更新）

本文档记录 thspypc 与 hexin 客户端 8901/9601 登录协议的完整字节级对比结论。
**取代 HANDOFF.md §2（2026-07-23 版）** 中已被推翻的旧分析。

## 2026-08-17 根因闭环：没有 K，两个字段都是长度

> 本节取代下文所有“`account_type/K` 是版本常量或票据代际配对”的解释。
> 复用上一次逆向留下的 loaded-image 地址修正、历史 pcap 和 `probe_check_k.py`
> 后，跨四种票据长度确认：所谓 account_type 前两字节与 K 都只是长度编码。

### 两个真实公式

Passport64 base64 解码后的 raw payload 前五字节是：

```text
uint16_le raw_payload_length
uint8     kind             # PC 抓包恒为 6
uint16_le head_length      # PC 抓包恒为 128
```

即：

```python
raw[:5] = struct.pack("<HBH", len(raw), 6, 128)
```

登录 body 中 `zh_CN.GBK` 后面的两个字节也不是 `check + 固定 0x09`，而是：

```python
suffix = struct.pack("<H", len(fixed) + len(passport64) + 1)
```

其中 `+1` 与完整 FD 帧后实际发送的单字节换行分隔符吻合；也可保守理解为协议的
单字节分隔/终止位。长度公式本身已由全部样本确定。过去反算的：

```text
K = (check_low_byte - len(fixed)) & 0xff
```

自然等于：

```text
K = (len(passport64) + 1) & 0xff
```

因此 K 没有独立来源、无需从配置或服务端逆向；suffix 的高字节也必须动态编码，
不能固定为 `09` 或 `07`。

### 跨样本验证

| raw 长度 | raw[:2] | base64 长度 | STANDARD fixed=203 | shell fixed=169 | 旧称 K | 来源 |
|---:|---|---:|---|---|---:|---|
| 1256 | `E8 04` | 1676 | `58 07` | `36 07` | 141 | 普通账号 2026-08-09 |
| 1722 | `BA 06` | 2296 | `C4 09` | `A2 09` | 249 | Level2 新票 2026-08-16/17 |
| 1726 | `BE 06` | 2304 | `CC 09` | `AA 09` | 1 | Level2 2026-08-05～10 |
| 1736 | `C8 06` | 2316 | `D8 09` | `B6 09` | 13 | Level2 缓存票 2026-08-11～16 |

MANUAL fixed=209 的历史值 `D2 09`（2304 字符票）和 `DE 09`（2316 字符票）
也逐帧满足同一公式。离线验证工具：
`tests/analyze_login_length_fields.py`，只输出长度和结构字节，不输出票据内容。

### 2026-08-16 项目失败的精确解释

失败抓包 `project_login_20260816.pcapng` 同时有两个过期长度：

- 实际 raw 长 1724，但头仍硬编码 `C8 06`，声明成 1736；
- 实际 base64 长 2300、STANDARD fixed=203，正确 suffix 应为
  `203+2300+1=2504=0x09C8`，代码却仍发旧长度的 `D8 09=2520`。

过滤尾随 `|` 产生的空字段后 raw 变成官方的 1722；正式实现现在根据最终 raw
长度生成 `BA 06`，并根据实际 base64/fixed 长度生成 `C4 09`，以后字段值长度变化
也不需要再抓新“配对”。

### 实现与活网闭环

- `LoginProtocolProfile.account_type` 只保留兼容名称，内容是
  `00 00 06 80 00` 模板；`build_passport64()` 在 payload 完成后动态回填前两字节。
- 所有 STANDARD/MANUAL/BOARD/L2 suffix 统一按 16 位 wire-tail 长度生成；删除
  `check_k`、legacy C8 profile 和普通账号的固定 `58 07/5E 07` 特例。
- 2026-08-17 活网：动态实现 MAIN 登录 `139.9.188.254`（当时属于
  `main.123ths.com`）成功；另刷独立票据后，L2 无用户名壳登录
  `8.134.115.123`（shlv2）成功。两者长度声明均与实际值一致。
- `tests/verify_all_logins.py` 随后完成 7/7 角色冒烟：MAIN、SH_L2、SZ_L2、
  REALORDER、BOARD、BOARD_CONSTITUENT、BOARD_STATS 全部成功。三次完整冒烟中
  首轮拒绝曾发生在 SH 和 SZ，也跨越 `8.134.*` 与 `122.9.*` 节点；服务端均返回
  “通行证有被修改的痕迹”，自动刷新票据、轮换节点后成功。另一次带 generation/
  Passport 摘要的聚焦复测中，三代票据均不同，MAIN→SZ→SH 又全部首轮成功。
  因此首轮 `-1` 可重复但非必现，且不绑定市场、节点或云网段，更像服务端/节点
  会话状态用通用文案拒绝；它不是动态长度公式回归，也没有证据表明新票内容被
  本地修改。
- 修正了一个独立的并发隐患：L2 `ConnectionFactory` 以前虽然执行
  `authenticate(force=True)`，却丢弃返回的不可变 `AuthMaterial`，随后从全局
  current 取票。现在材料从鉴权调用端直传 `_open_manual_push_connection()`；
  后台双市预热也各自持有独立材料，避免并发时 current 被覆盖而串票。
  顺序冒烟在此修正后仍可能出现上述 SH 首轮拒绝，证明该并发隐患与当前服务端
  拒绝是两个问题，不能把前者误报成后者的已证实根因。
- 冒烟脚本的 `order_details` 耗时包含三路业务请求（挂单、买撤、卖撤），不能把
  例如 `46.5s` 直接解释成 L2 登录耗时；复测中相同 MAIN→SZ→SH 全流程约 4 秒。
- 2026-08-17 后续两次 BOARD_STATS 均已完成 9601 登录，但 `statscalc` 业务响应
  等满 15 秒后返回空。这是登录成功后的独立业务可用性问题。冒烟脚本现已显式
  检查 `ConnectionRole.BOARD_STATS` 活动连接，并分别输出 `login=VerifyCode=0` 与
  `统计=0（业务空响应或超时）`，避免把“方法降级返回空”本身误当登录证据。
  同日官方客户端看盘页+94页新抓包进一步确认：当前板块排行全走 8901，9601
  WDCS 连接只有心跳、没有 statscalc 请求；故该角色只能说明旧辅助通道登录，
  不能代表当前板块排行功能。
- STANDARD 是否长期由官方发往 shlv2 仍是独立的路由问题；长度算法闭环不要求
  修改当前 MAIN 路由。

### 对上一次简单逆向的复盘

上次 `reverse_k_scan_login_refs.py` 已正确发现 loaded image 的运行时基址修正、
字符串 getter/funclet 和间接引用，但因为当时把 K 当成独立状态，继续追 login
构造函数无法得到来源。本次重新使用历史 pcap 后，`BE/1`、`C8/13`、`BA/249`
以及普通账号 `E8/141` 全部被长度公式同时解释，静态扫描不再是必要路径。

新旧 `6.pass` 均为高熵存储；新文件比旧文件短 16 字节，末尾 1512 字节相同。
这与变长票据块一致，但无需解密 `6.pass` 才能生成上述字段。

## 2026-08-16 登录回归（历史中间结论，已被 8/17 长度公式取代）

> 本节是当前最高优先级结论，**取代本文后面关于“C8/K=13 是客户端版本常量、
> 可以永久硬编码”的判断**。后面的 8/10～8/11 内容保留作历史调查记录，不能再
> 单独作为当前实现依据。

### 结论分级

#### 已证实

1. 项目在 2026-08-16 用现有实现重新 HTTP 鉴权后，发出的 Level2 登录组合仍是
   `account_type=C8 06 06 80 00`、`K=13`。STANDARD 壳 `fixed=203`，所以 suffix
   为 `D8 09`。main/ifindhq 候选服务器均在收到完整登录帧后直接关闭连接，没有
   返回 `Reply=login`。
2. 同一台机器、同一官方客户端版本 `9.60.20.0031`：
   - 复用旧缓存票据时仍发 `C8/K=13`，8/8 个 8901 登录均 `VerifyCode=0`；
   - 移走 `Passport/6.pass`、强制重新 HTTP 鉴权后，全部 8 个登录改发
     **`BA 06 06 80 00 / K=249`**，8/8 均 `VerifyCode=0`。
   这直接证明 `(account_type, K)` 至少与票据代际/鉴权结果有关，不能再解释为
   “只由客户端二进制版本决定”。
3. 官方新票据的无用户名壳 `fixed=169`，suffix=`A2 09`；唯一带用户名的
   STANDARD 壳 `fixed=203`，suffix=`C4 09`。两者均满足：

   ```text
   check = (len(fixed) + 249) & 0xff
   ```

4. 官方新票据的 Passport64 为 2296 个 base64 字符，解码后 1722 字节，尾部是
   `...sv=...\r\n\x00`。项目旧实现为 2300 个字符/1724 字节，尾部多一个空字段：
   `...sv=...\r\n\r\n\x00`。原因是 HTTP passport 以 `|` 结束，
   `build_passport64()` 保留了 `split(b"|")` 产生的空段。两边保留的 44 个
   key/value 字段集合相同（动态值只有正常的签发时间差异）；过滤空段即可对齐。
5. 用项目自己的**新 HTTP 鉴权结果**，仅替换为 `BA/K=249` 并过滤 Passport64
   空段后，按诊断目的只竞速 `shlv2.123ths.com` 候选服务器，STANDARD 登录成功：
   `8.134.115.123:8901` 返回 `VerifyCode=0`。这闭环证明当前 HTTP 鉴权参数不需要
   为本次故障修改，问题至少包含上述两个 TCP 字节差异。
6. HTTP 鉴权生成的一张通行证在首次 `VerifyCode=0` 后即被消费；所有验证均使用
   `thspypc.testing.login_socket_for_domains()` 并保留获胜 socket，没有拿成功票据
   再串行尝试其他 host。
7. 修复落入正式实现后，通过 `thspypc.testing.get_client()` 做了一次全新 HTTP 鉴权
   和现有 MAIN 路由端到端验证：`BA/K=249`、Passport64 长度 2296，获胜地址
   `8.134.123.179:8901` 当时解析归属 `ifindhq.123ths.com`，登录成功。它证明当前
   生产 MAIN 候选策略无需为本次故障改到 shlv2。
8. MAIN 验证结束后另刷一张独立票据，用正式 `LoginIdentity.L2` 无用户名壳和
   `thspypc.testing.login_socket_for_domains()` 竞速 shlv2：body suffix=`A2 09`，
   `8.134.115.123:8901` 返回 `VerifyCode=0`。因此 BA/K249 对 STANDARD 与 L2 壳
   均已有正式实现的活网证据。

#### 仅观察到，尚不应固化为代码

- 官方新鉴权抓包中，8 条 8901 登录里只有 1 条是带 `thsuser` 的 STANDARD 壳，
  该连接落在当前 `shlv2` 地址；其余 7 条是无用户名壳。
- 旧项目票据即使强制发往 shlv2 仍失败，因此“改路由”不是本次故障的充分修复。
- 目前只有一次新鉴权冷启动样本，尚不能确认 STANDARD 永久从 main/ifindhq 改到
  shlv2，也不能确认这个连接在官方内部承担的角色。**本次先不改生产 MAIN 路由**；
  应继续积累多次冷启动、不同日期/账号样本，并关联登录后的首个 init/订阅帧再定性。
- 项目用相同新 profile 在 ifindhq 成功，只能证明“路由不是修复 BA/K249 登录所必需”；
  它并不能解释官方为什么把那条 STANDARD 放到 shlv2。

#### 尚未解释

- `BA/K=249` 的来源和选择条件：它可能来自 mainverify 响应、票据/`6.pass` 元数据、
  客户端本地映射表，或鉴权阶段的其他配置；当前只知道配对和校验算式，不知道
  “为什么本次选 BA/249”。对项目明文 mainverify 抓包的字段名扫描没有发现显式
  `account_type`/`check_k` 字段，因此下一步应优先检查 signature/票据代际与客户端
  本地映射表，而不能只在普通 XML 属性中找同名值。
- 服务端是否会继续轮换出新的配对，以及旧的 `BE/1`、`C8/13` 能保留多久。
- STANDARD → shlv2 是长期路由规则、容灾选择，还是某个特定角色的连接。

### 抓包与可复核证据

| 文件 | 内容 |
|---|---|
| `captures_live/project_login_20260816.pcapng` | 项目 C8/K13 登录失败 |
| `captures_live/hexin_login_20260816.pcapng` | 官方复用旧缓存票，C8/K13 成功 |
| `captures_live/hexin_fresh_auth_20260816.pcapng` | 官方强制新鉴权，BA/K249，8/8 成功 |
| `captures_live/hexin_fresh_auth_tls_20260816.pcapng` | 新鉴权 TLS/网络辅助证据 |
| `captures_live/route_probe_shlv2_20260816.pcapng` | shlv2 路由对照探测 |

抓包含真实登录材料，只保存在本机且被 git 忽略，禁止提交或在日志中输出
Passport64、signature、sk、sv 等值。

> 解析校正：调查过程中曾因把 12 字节 `fd fd fd fd + length` 帧头重复计入偏移，
> 短暂误报过 `account_type=43`/suffix=`07`。重新按 login body 起点解析后，正确值
> 是本文记录的 `BA 06 06 80 00`、`A2 09`/`C4 09`；不要引用那次中间结果。

### 8/16 当时的修复方向（历史记录）

- 8/16 曾先把 Level2 新鉴权 profile 改为 `BA/K=249` 并过滤空段；8/17 已进一步
  删除该硬编码，改为 raw/base64 两处真实长度的动态生成。
- 暂不修改 MAIN 路由，避免把单样本观察误当协议规则。
- 当时认为还需逆向“配对来源”；8/17 已证明不存在该来源，变化完全由最终 payload
  长度决定。保留本段只是为了说明调查如何收敛。

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

thspypc 的旧登录帧用 `account_type=BE / K=1 / L2 通道带 UserName(thsuser)`。
8/10 前服务器宽容，不严格校验这些组合；8/10 起收紧。

> **2026-08-11 更新**：8/10 那次 -1 故障的根因在 commit 592a5ec 的 5 个改动
> 里，但当时无法区分哪个改动真正修了故障（5 个捆绑验证）。8/11 的调查确认：
> - **account_type（BE→C8）和 K（1→13）是配对的**，不能单独改一个。
>   thspypc 旧代码发 `BE/K=1`，新版发 `C8/K=13`，两组配对服务器都接受。
>   但**混搭**（如 C8/K=1）会被拒。
> - **L2 通道改用无 UserName 壳**（`LoginIdentity.L2`）是必要的修正——
>   旧代码用 STANDARD（带 thsuser）登 L2，被严格服务器拒。
> - 8/10 -1 故障最可能的直接原因是 **L2 通道的 UserName 问题**，而非 check/K。
>   （check 字节服务器确实校验，但它校验的是 (account_type, K) 配对一致性，
>   不是 K 等于某个固定值。）
>
> 完整根因分析见下方"K 值根因调查"章节。

8/9 周日到 8/10 周一，同花顺服务端做了更新，从宽容校验切换成严格校验。
hexin 客户端不受影响（它发的帧本来就符合严格校验）；thspypc 发的旧组合
被拒。commit 592a5ec 把 thspypc 对齐到新配对（C8/K=13）+ L2 无 UserName 壳，
修复后 7/7 通过。

> ⚠️ **教训**：不能用"旧代码能登"反推"代码是对的"。服务器的宽容校验会掩盖
> 帧内容差异。只有和 hexin 真实帧做**字节级对比**才能确认帧是否正确。
> 2026-07-23 的旧逆向就是吃了这个亏——没抓 hexin 真实帧，从自己帧反推公式，
> 碰巧 ifindhq 宽容能过，就以为对了。
>
> ⚠️ **8/11 补充教训**：抓包结论必须标注**来源电脑和 hexin 客户端版本**。
> 不同电脑可能装不同版本的 hexin，发的 (account_type, K) 配对不同。
> 把一台电脑的 hexin 行为当成"所有 hexin 的统一行为"会导致错误结论。

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
check = (len(fixed) + K) & 0xFF
```

其中 `fixed` = `Ask=login` 开头到 `Passport64=`（不含值）的 GBK 编码字节数，
`K` 是一个随 hexin 客户端版本变化的常数（**不是固定值**）。

实测验证（2026-08-10 hexin 8 帧抓包）：

| 身份 | fixed 长度 | check 字节 | K 值 |
|---|---|---|---|
| MAIN（带 UserName）| 203B | `0xD8` | K=13 |
| L2/fu4（无 UserName）| 169B | `0xB6` | K=13 |

> ⚠️ **K 值和 account_type[0] 配对，是客户端版本标识（不是运行时状态、不是版本相关性）。**
>
> | account_type[0] | K | 客户端版本 | 来源 |
> |---|---|---|---|
> | `0xBE` | 1 | 旧版 hexin | 这台电脑 hexin 缓存的 8/7 passport（2026-08-11 双抓包确认）|
> | `0xC8` | 13 | 新版 hexin / thspypc | 另一台电脑 hexin（2026-08-10 抓包）+ thspypc 当前代码 |
>
> **服务器同时接受两种配对**。只要 (account_type, K) 配对一致即可登录。
> thspypc 硬编码 `C8/K=13`（= 新版客户端），在任何电脑上都可用——account_type
> 和 K **不是电脑指纹**（imei/Mac64 相同时 account_type 仍可不同），而是客户端
> 版本标识。代码不需要随电脑变化。
>
> 另有一种 `0x07` 尾帧变体（offset 14 = `0x07` 而非 `0x09`），使用完全不同的
> check 算法（`(len+141)&0xFF`），出现在部分历史 pcap 中，当前不影响 thspypc。

### K 值根因调查（2026-08-11 完整复盘，推翻 8/11 01:21 的静态分析结论）

**本节取代 commit 6421913 的"K 值来源逆向调查"。那次静态分析的方向是错的——
K 没有运行时来源，它是和 account_type 配对的客户端版本标识。**

#### 调查过程

1. **静态逆向（commit 6421913，8/11 01:21）**：在 hexin 加载映像上追 check 计算
   的全局变量写入点。撞墙——`Ask=`/`Reply=` 字面量不在镜像里（运行时拼接），
   login 字段名（thsuser/zh_CN.GBK/...）被 thunk getter 表间接引用，无法定位
   login body 构造函数。（阶段 1a 记录：`tests/reverse_k_scan_login_refs.py`）

2. **probe 工具开发**：写 `tests/probe_check_k.py`（纯 scapy，不依赖 tshark），
   反算 K = `(check_byte - fixed_len) % 256`。在 7/23 pcap 上验证 14/14 流 K=1。
   （阶段 2a）

3. **活网验证（阶段 2b，推翻中间假设）**：
   - 8/11 09:14 抓包：这台电脑 hexin 发 **BE/K=1**，7/7 VerifyCode=0 ✓
   - thspypc 发 C8/K=13：7/7 VerifyCode=0 ✓（`verify_all_logins.py`）
   - thspypc 发 C8/K=1（配对错误）：连接被关闭 ✗
   - thspypc 发 C8/K=0,2,99：全部 ✗
   - thspypc 发 **BE/K=1** 到 hexin 用的服务器：✓（`verify_k_irrelevance.py`）

4. **逐字节 diff（阶段 2c）**：hexin 帧和 thspypc 帧**唯一差异是 check 字节**
   （hexin=0xcc/K=1 vs thspypc=0xd8/K=13），其余 2521 字节完全相同
   （`tests/_diff_hexin_vs_thspypc_login.py`）。

5. **passport 缓存确认**：hexin 两次抓包（09:14 和 13:27）的 passport raw SHA
   完全相同——hexin 复用了 8/7 签发的缓存 passport（signdate=2026080703，
   account_type=BE）。thspypc 每次重新 HTTP 鉴权，拿到 8/10 签发的新 passport
   （signdate=2026081005，account_type=C8）。

#### 关键证据

| 数据点 | account_type | K | VerifyCode | 来源 |
|---|---|---|---|---|
| 这台电脑 hexin（8/11 双抓包） | BE | 1 | 0（7/7）| hexin 缓存 8/7 passport |
| 另一台电脑 hexin（8/10 抓包） | C8 | 13 | 0（8/8）| 另一台 hexin 新版客户端 |
| thspypc C8/K=13 | C8 | 13 | 0（7/7）| 当前代码，任何电脑 |
| thspypc C8/K=1（配对错） | C8 | 1 | ✗ | 活网验证 |
| thspypc BE/K=1（配对对） | BE | 1 | ✓ | 活网验证（hexin 服务器）|

#### 8/11 01:21 静态分析为什么错

那次分析基于"8/11 起 hexin K 从 1 变 13"的假设，去追 K 的"运行时全局状态"。
但这个假设本身是错的——它把**另一台电脑的 hexin（新版 C8/K=13）**当成了
"所有 hexin 8/10 起的统一行为"。实际上：

- 这台电脑 hexin 仍是旧版（BE/K=1），8/11 抓包确认
- K 没有运行时来源，是和 account_type 配对的客户端版本常量
- 静态逆向自然找不到"K 的全局变量写入点"——因为它不存在

**教训**：抓包结论必须标注**来源电脑和客户端版本**，不能假设所有 hexin 行为一致。
两个 hexin 客户端（不同版本）在同一服务器上可以发不同的 (account_type, K) 配对。

#### probe_check_k.py 的用途

`tests/probe_check_k.py` 不是"找新 K 值"的工具（K 不需要动态找），而是**验证
(account_type, K) 配对一致性**的诊断工具。如果未来 thspypc 出现 -1 回归，
跑它对比 hexin 抓包的 account_type 和 K，确认配对是否仍被服务器接受。

#### 静态分析遗留的地址修正

commit 6421913 记录的地址表有系统性偏差（image base 0xa50000 语境下的 VA
需减去 base 才是 RVA）。实测修正（镜像 `captures_live/hexin.dmp.loaded.bin`，
运行时 base `0xa50000`，RVA == 文件偏移）：

- login 字段名串池在 **ASCII**（非 handoff 说的 UTF-16），RVA `0x1a8911c` 起
  （`thsuser`/`__manual`/`youareadog`/`zh_CN.GBK`/`Password`/`VerifyType`/...）
- thsuser getter `0x22eb970` 实际是 22B（含 security cookie 检查），不是 26B 桩
- `Ask=`/`Reply=`/`Ask=login` 在镜像里 count=0（运行时拼接，handoff 这点是对的）

## 五处协议修正（全部 2026-08-10 确认并修复）

### 修正 1：account_type[0] 0xBE → 0xC8（与 K 值配对改动）

**文件**：`src/thspypc/features/auth_protocol.py:42`（PC_LEVEL2_LOGIN_PROFILE）

8/10 抓包（另一台电脑的新版 hexin）8/8 帧（MAIN + L2 + fu4）的 head128[:5]
全是 `C8 06 06 80 00`。thspypc 旧值 `BE 06 06 80 00` 被严格服务器拒（-1）。

> **2026-08-11 更新**：account_type 和 K 是**配对**的——`BE` 配 K=1，`C8` 配 K=13。
> 这台电脑的旧版 hexin 仍发 `BE/K=1`（复用 8/7 缓存 passport），另一台电脑的
> 新版 hexin 发 `C8/K=13`。服务器两组都接受，但不能混搭（如 C8/K=1 会被拒）。
> thspypc 选 C8/K=13（= 新版客户端配对），任何电脑上都可用。详见"K 值根因调查"。

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

### 修正 3：check 字节公式 +1 → +13（与 account_type 改动配对）

**文件**：`src/thspypc/features/auth_protocol.py:220,259`（BOARD 分支 + 通用 fallback）

两处 `(len(fixed) + 1) & 0xFF` → `(len(fixed) + 13) & 0xFF`。

- **通用 fallback**（:259）：影响 MAIN(L2 STANDARD)、SH_L2/SZ_L2(L2)、REALORDER、STATSCALC、
  BOARD_CONSTITUENT。
- **BOARD 分支**（:220）：影响 fu4 板块通道。

> **2026-08-11 更新**：K 值和 account_type[0] 配对（BE→K=1, C8→K=13）。改 account_type
> 从 BE 到 C8 的同时**必须**改 K 从 1 到 13，否则配对不一致会被服务器拒。
> 当前代码硬编码 `K=13`，匹配 `account_type=C8`。详见"K 值根因调查"章节。

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
2. **check 公式 `K=13` 配 `account_type=C8`**：所有身份（STANDARD/MANUAL/BOARD/L2）都用
   `(len+13)&0xFF`。**K 和 account_type 必须配对**——`BE/K=1` 和 `C8/K=13` 都合法，
   但混搭（如 C8/K=1）会被服务器拒。thspypc 选 C8/K=13（新版客户端配对）。
3. **严格 vs 宽松服务器**：ifindhq 不校验 account_type/check（宽松）；main/shlv2/szlv2/fu4
   严格校验。修复前 thspypc 只能登 ifindhq；修复后全部可登。
4. **sk/sv 必须保留**：thspypc 的 head128（移植自 thspy Mac 版 `signature_to_nibbles`）没有
   把 sk/sv 编码进 signature，所以必须保留 sk/sv 明文字段。这点旧分析是对的。
5. **account_type/K 不是电脑指纹**（8/11 确认）：同一台电脑 thspypc(C8/K=13) 和
   hexin(BE/K=1) 都能登。它们是**客户端版本标识**，thspypc 在任何电脑上用
   C8/K=13 即可，不需要随电脑变化。
