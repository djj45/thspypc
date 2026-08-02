# 个股历史分时省略型 codec —— 第2步官方客户端逆向定位结果

> 状态：已沿 Playbook §7 阶梯（rung 4 已加载镜像静态）定位到**记录解码全链**，
> 并在汇编层确认字段级编解码机制（7-bit 变长）；完整 23 字段 oracle 的捕获
> 需 rung 5（Unicorn）/rung 7（动态 hook）。创建：2026-07-30。
> 前序：[`HISTORY_TIMELINE_OMISSION_STEP1_FINDINGS.md`](HISTORY_TIMELINE_OMISSION_STEP1_FINDINGS.md)
> （第1步：DP 结构对齐、控制字 `0x1600` 形态归纳）。

## 一、环境与工具准备

- **加载镜像**：`captures_live/hexin.loaded.bin`（47,886,336B）。它是 UPX 解包后的
  hexin.exe 内存 dump，由 `reverse_hexin_minidump.py extract-module` 从全进程
  minidump 重建。**关键性质：RVA == 文件偏移**，`image_base=0xd50000`，3 节
  （`UPX0` 0x1000–0x1d5f000、`UPX1` 0x1d5f000–0x2d8c000、`.rsrc`）。
- 因此标准 `pefile` 的节映射（`reverse_pe_rtti.py` / `reverse_pe_string_xrefs.py`
  按 `PointerToRawData` 映射）**对本 dump 失效**；这两个脚本里的
  `offset_to_va` 会抛「file offset outside PE sections」。
- 已在 `.venv` 安装 `pefile`、`capstone`、`unicorn`（playbook §19 的 RE 脚本依赖）。
- 新增 `tests/reverse_hexin_loaded.py`：**针对本 dump**（RVA==offset）的 RE 辅助，
  提供 `find_rtti` / `find_string_refs` / `find_code_refs` / `disasm`，全部以 RVA
  为输入。它复用 `reverse_hlib_memory.parse_image`。

> 注意两个不同的 `0x1600`：playbook §5.3/§9 的 `0x1600` 是**外层帧分发**（normalizer
> 输出之后）；本文与 STEP1 里的 `00 16` 是**省略记录内字段槽的控制字**。两者无关。

## 二、已定位的记录解码全链（RVA，本 dump）

从 RTTI 锚 `CHQuoteFile` 顺调用链向下，全部 RVA 已用反汇编确认（每段都从
`55 8b ec` 标准 prologue 起）：

| RVA | 角色 | 证据 |
|-----|------|------|
| `0x1acb2bc` | `CHQuoteFile` vtable | RTTI `.?AVCHQuoteFile@@` → COL → vtable |
| `0x127c8b0` | `CHQuoteFile::parse`（vtable[5]） | 读版本、`call 0x136c430` 分类、按 `esi` 分支选记录解码器 |
| `0x136c430` | 版本前缀分类器 | 比 `hd1.`/`hd1.0`/`hd1.2`/`hd1.3`，把位标志（1/2/3/5/0x10/0x10000000）或入输出 dword；**不**按 flag 分发 |
| `0x136bbe0` | **记录解码器**（`esi==1` 分支） | 取记录数组 `0x1fcbd40`、记录数 `[edi+8]`、字段表 `[edi+0xc]`、记录基址+`[edi+0x1c]`，`call 0x136b8e0` |
| `0x136b8e0` | 表头/字段表解析 | 解 `hd1.0\0`（`call 0x13dc240` 跳过 5B）、`[ebp+0x10]==0x10` 版本分支、建字段表 `0x20bb100`，`call 0x136ba90` |
| `0x136ba90` | 字段表 + 记录体抽取 | 解 `fc` 个 5B 字段描述符（`0x13dc240`），`call 0x139a6d0`（核心） |
| `0x139a6d0` | **核心按字段抽取器** | 循环：`call 0x13dc220` 读变长字段 → 写入输出；带位级 transpose（`shl/shr/or [edi]`） |
| `0x691d40` | **变长字段解码器** | `0x13dc220`/`0x13dc240` 的公共内层；调 `0x691db0`（见下）取变长字节，再 `shl ecx,7; or ecx,al` 组装。首字节 `& [ebp+0x14]`（0 读 / 0x40 标志），`neg/sbb` 造出「字段是否省略」标志 |
| `0x691db0` | **变长字节扫描器** | 读最多 5 字节；遇 `>=0x80` 的字节剥掉 `0x80` 后停止（终止符），返回消费字节数。**注意 RVA**：Capstone 打印的绝对 VA 是 `0x13e1db0`，真 RVA = `0x691db0`（曾因把它当 RVA 而错位反汇编） |

调用方 `0x136bbc3` 处压栈顺序（cdecl）：`edi`(记录指针)、`[ebx+4]`(输出缓冲)、
`byte[eax+0xd]>>2`(字段数)、`[eax+8]`。

## 三、字段级编解码机制（汇编级确认）

### 变长字节扫描器 `0x691db0`

```asm
0x691db0: ... mov edi, [ebp+0x14]   ; edi = 最大字节数（调用方传 5）
0x691dc5:   mov cl, [edx]           ; 取一字节
0x691dca:   mov [eax+ebx], cl       ; 存入输出
0x691dcd:   cmp cl, 0x80
0x691dd0:   jae 0x691ddf            ; >=0x80：终止符分支
0x691dd2:   inc eax; cmp eax, edi; jl loop
...
0x691ddf:   and cl, 0x7f            ; 剥掉 0x80 终止位
0x691de3:   mov [eax+ebx], cl; inc eax; ret
```

**语义**：每个字段是一串「值字节 <0x80」+ 一个「终止字节（带 0x80 位，低 7 位
也是数据）」。扫描器最多读 5 字节，遇到 `>=0x80` 就剥掉 `0x80` 停下，返回消费
字节数；若 5 字节内没遇到终止符，返回 -1（错误）。

### 变长字段组装器 `0x691d40`

```asm
0x691d62: call 0x691db0          ; 扫描器，esi=消费字节数
0x691d70: mov al, [ebp-0xc]      ; 输出缓冲区首字节
0x691d73: and al, [ebp+0x14]     ; & 掩码（读变体 0x40 / 跳过变体 0）
0x691d76: movzx ecx, al
0x691d79: neg ecx; sbb ecx, ecx  ; al!=0 -> ecx=0xFFFFFFFF；al==0 -> ecx=0
0x691d83: movzx eax, [ebp+edx-0xc]
0x691d89: shl ecx, 7; or ecx, eax  ; 大端 7-bit 拼接
0x691d92: mov [edi], ecx          ; 写 4 字节值
```

**两个关键语义**：

1. **每字节 7 位、大端序拼接**（`shl 7; or`），最多 5 字节 → 35 位，足够装 u32。
2. **首字节的 bit6（0x40）是「字段省略」标志**：`and al, 0x40` + `neg/sbb` 把
   「该字段是否被省略」编码进组装结果的最高位。被省略的字段值不在线上，需由
   解码器的前值/状态恢复——这正是 STEP1 看到的 `00 16` 控制字。

### full 记录 vs 省略记录：两种路径并存

- **full 记录**：bar 与 dt10/dt13/dt19 等是**裸 LE32**（实测
  `97 72 e5 07`=132477591，**非**变长）。STEP1 已逐点验证 dt13/dt19 与 thsdk
  一致。
- **low2 省略记录**：bar 高位字、dt10 等被 `00 16` 控制字替换（对应
  `0x691d40` 的 bit6 省略分支），其余字段（dt13/dt19/Level2）仍是裸 LE32。

### 被省略的 dt10 无法靠简单规则恢复（关键负面结论）

对 000001 的 16 条 low2 记录用 thsdk oracle 反验：

- 「复用上一条 dt10」：仅 8/16 命中；
- 「复用上一条 full 记录的 dt10」：仅 2/16 命中。

→ 被省略的 dt10 真值存在于解码器的跨记录状态里，**线上字节 + thsdk 都不足以
恢复**，仍需官方客户端解码 oracle（交接文档第0步阻断项未解除）。

### 省略编码的字节级规律（仿竞价 dt49 的语料反推，部分进展）

用 `tests/analyze_history_timeline_omission.py` 逐字节反推，确认：

- **low2 记录是定宽 92B**，不是变长流（排除了「整条记录走 `0x691d40` 变长」的
  假设）；`>=0x80` 的字节在记录各处密集出现，是裸 LE32 值的正常组成。
- **dt10 槽只保留最低 1 字节**（= target raw 的 byte[0]），高 3 字节被
  `00 16 00` 控制区替换。全零 `00 00 00 00` = 整字段沿用前值。
- THS float 价格的 byte[0:2]（u16 mantissa 低位）是价格的线性函数（每 1 分钱
  差 100），因此 **byte[0] 携带了价格变化的信息**。

但 **byte[1] 的精确恢复规则无法从语料单独确定**：byte[0] 的有符号增量
（mod 256）与 byte[0:2] 的实际增量（±100/分）之间没有确定映射（试过的
「prev_b0b1 + signed_delta(slot_b0)」规则只 3/6 命中）。byte[1] 的真值在客户端
解码器的跨记录状态里，**纯语料分析到此为止**——这印证了 playbook §12 把纯语料
路径列为「已证失败」、以及沪市竞价只有走「二进制逆向 → Unicorn → Python 移植」
才闭环的结论。

因此闭环仍需二进制逆向：把 `0x136b8e0`（吃记录区、建字段表对象、调解码链）的
**完整 C++ 对象状态**喂进 Unicorn（需构造 `this` 虚表），或取得同标的成对 oracle
（重发碰 full 型）。动态 hook 已排除（反调试严格）。

## 四、为什么停在 rung 4（静态），后续需要的 rung

Playbook §7 阶梯，本任务现状：

| rung | 状态 | 说明 |
|------|------|------|
| 4 已加载镜像静态 | ✅ 已完成 | 定位到全链 + 变长机制；深 vtable/switch 表不再阻塞——变长/省略语义已在 `0x691d40`+`0x691db0` 坐实。 |
| 5 Unicorn | ✅ parse 跑通；❌ 省略恢复不在 parse | `tests/emulate_chquote_parse.py` 成功模拟了构造函数 `0x127c570`（含 FS/SEH 段设置）+ parse `0x127c8b0`，vtable 正确写入 `0x281b2bc`，堆上分配了对象。但 **parse 只是容器解析器——它把记录区字节原样搬到堆上，对 low2 省略字段（dt10 等）不做任何恢复**（堆上 low2 记录字节与线上完全一致，dt10 仍为 `0x00000000`）。省略恢复发生在更下游的字段读取层（getter vtable 方法 + `0x691d40` 变长解码器 + 跨记录状态），不在 parse。 |
| 7 动态 hook | ❌ 本环境不可 | 同花顺反调试严格（用户确认），不在运行中的 hexin.exe 上 attach。 |

**关键负面结论**：`CHQuoteFile::parse` **不做省略恢复**。它是一个纯粹的容器解析器，
把 `hd1.0` 记录区字节搬到堆对象里。省略字段（dt10 价格等）的真值恢复发生在同花顺
UI/业务层调字段 getter 时——getter 用 `0x691d40` 变长解码器逐字段读 + 维护跨记录
状态。这条 getter 调用链是更深的 C++ 对象方法分发，且依赖运行时状态（前值缓存），
不是一个能直接喂字节流、吐字段值的纯函数。

因此「逆向一个纯函数翻成 Python」这条路（沪市竞价 `0xf74260` 的成功模式）**在本
任务里不适用**——因为省略恢复不是一个独立函数，而是散布在字段读取的状态机里。

## 五、可直接推进的下一步（按代价从低到高）

省略恢复不在 parse，而在字段 getter 状态机。剩下能闭环的路：

1. **同标的成对采集**（第0步路径②，最现实）：对 000001/20260514 重发，碰服务端
   下发 full 型（dt10 不省略）；用 STEP1 DP 对齐拿 full 真值，再对 low2 同标的
   逐字段对齐，反推省略恢复规则。full 和 low2 是同标同日，字段语义一致。
2. **模拟字段 getter 调用链**：parse 跑通后对象在堆上，逐个调 vtable getter
   方法（需搞清哪个 getter 读 dt10、它怎么调 `0x691d40`），让状态机自然推进。
   工作量大（要逆向 getter 的对象/状态依赖）。
3. 动态 hook 已排除（反调试严格）。

## 六、复用的 extern 地址（harness 用，本 dump 已验证存在）

```
malloc  VA=0x2332ba2  RVA=0x15e2ba2
free    VA=0x23310d9  RVA=0x15e10d9
memcpy  VA=0x2321290  RVA=0x15d1290
memset  VA=0x2321f10  RVA=0x15d1f10
（与 emulate_hexin_normalizer.py 的 extern 集一致，多一个 memset）
```

## 七、本次新增/改动文件

- `tests/reverse_hexin_loaded.py`（新增，dump 感知的 RE 辅助，已验证可跑）。
- `tests/emulate_history_timeline_field.py`（新增，`0x691d40` Unicorn harness，
  单字段探针；正确解码需整链）。
- `src/thspypc/codecs/history_timeline_omission.py`（**新增务实 codec**）：
  DP 对齐 241 条 + 安全字段解码，full 记录返回完整字段，low2 记录把被省略字段
  标 `missing_fields`、`complete=False`，**不在错位数据上猜值**。已通过 CI 回归
  （dt13/dt19 逐点对 thsdk）。
- `tests/test_history_timeline_response.py`：新增 3 个 codec 回归用例。
- 本文档。
- `.venv` 新增 `pefile`/`capstone`/`unicorn`（**未**写进 `pyproject.toml`，因为
  是 RE-only 依赖；codec 本身不依赖它们）。

## 八、当前能力与剩余缺口

**能安全返回**：241 个 bar 全部恢复；full 记录 23 字段；low2 记录的 dt13/dt19/
Level2 等裸 LE32 字段；每条记录的 `complete` / `missing_fields` 元数据。

**仍不可用**：low2 记录里被 `00 16` 控制字占据的字段（dt10 价格、个别 Level2
字段），其真值在线上不存在，需同标的 oracle 才能恢复。交接文档 §六 验收第
1/2 条（≥2 股票×4 日期×23 字段、对客户端 oracle 精确匹配）仍未达成。
