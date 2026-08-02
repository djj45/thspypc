# 个股历史分时省略型 codec —— Unicorn 执行核验与变长结构更正

> 状态：用 Unicorn 实跑 + thsdk oracle 反查，**核验并裁决了前序文档的若干矛盾说法**。
> 决定性结论：(1) parse 走 esi==2 且对记录表只做单次整块 memcpy，不做任何字段解码；
> (2) 记录是**变长**的（物理步长 89–92B），不是定宽 92B——STEP1 的「定宽」说法需降级；
> (3) full/low2 两型与 `0x1600` 省略标记成立，满字段记录逐字段解码与 oracle 精确对齐。
> 创建：2026-07-30。
> 前序：[`..._CORRECTION_HANDOFF.md`](HISTORY_TIMELINE_OMISSION_CORRECTION_HANDOFF.md)
> （撤回 STEP2 分支定位）、[`..._STEP1_FINDINGS.md`](HISTORY_TIMELINE_OMISSION_STEP1_FINDINGS.md)
> （DP 对齐）、[`..._VARLEN_INVESTIGATION.md`](HISTORY_TIMELINE_VARLEN_INVESTIGATION.md)
> （三层结构）。

## 一、Unicorn 执行核验：parse 走 esi==2 且只 memcpy

`tests/emulate_chquote_parse.py` 已加分支硬断言 + 字段解析插桩，用完整
`_tmp_000001_subtable.bin` 输入实跑，证据链：

### 1. 分支硬断言：确认 esi==2 路径（文档 CORRECTION 的核心结论成立）

`parse`（RVA `0x127c8b0`）的 dispatch（反汇编坐实）：

| esi 值 | 调用点 RVA | 目标 | 性质 |
|--------|-----------|------|------|
| 0 | `0x127c95b` | `0x127ce20` | — |
| **2** | **`0x127c96d`** | **`0x136c390`** | **本样本命中** |
| 1 | `0x127c97f` | `0x136bbe0` | STEP2 误判，**未命中** |

实跑结果：

```
classifier_results: [2]          分类器 0x136c430 返回 2
dispatch_esi: 2                  dispatch 点(test esi,esi) ESI==2
branch_hits: esi2_call_site=1, esi2_entry=1, esi2_core=1
  esi0/esi1_call_site=0
forbidden_hits: []               STEP2 四函数(0x136bbe0/0x136b8e0/0x139a6d0/0x691d40)零命中
branch_ok: True
```

`0x136c390` 内部 `call 0x136c080`，故 esi==2 链 = `0x127c8b0 → 0x136c390 → 0x136c080`。
**CORRECTION §一 的结论被动态执行实证，STEP2 的 esi==1 全链确实不在本数据路径。**

### 2. 字段解析插桩：`0x136c080` 单次整块 memcpy，零字段解码

`0x136c080`（esi==2 字段解析器）每次调用处理一个字段，由调用者 `0x136c390` 逐字段
驱动；内部按描述符 `[esi+0]` 的 type 字节分发：type==0 走 memcpy，type1/2/3/5/6 走
各自解码器。但实跑：

```
field_type_total: 1              0x136c080 只被调用一次
type_counts: {0:1, 1/2/3/5/6:0}  单次调用是 type==0
decoder_hits: 全 0               type1/2/3/5/6 解码器零命中
memcpy_fields: [(src=0x60000128, dst=0x60000128, len=22264)]
                                单次 memcpy，拷 22264B = 242×92（dc×hs）
```

**结论：esi==2 路径把整张记录表当一个 type==0 原始 blob 单次 memcpy 一次，
没有任何字段级处理。** 省略恢复（dt10 等）绝不在 parse/`0x136c080`，必然在
parse 之后的下游（getter/commit 层）。这比 CORRECTION「parse 只是 memcpy」更精确：
**单次 memcpy、整表搬运、零字段解码**。

### 3. 发现并修复了 harness 一个真实缺陷

`0x136c080` 的 type==0 路径调用的是第二个 memcpy 副本 `0x2321810`（RVA `0x15d1810`），
与已 hook 的 `0x2321290` 逐字节相同、是并行冗余实现。原 harness 只 hook 了
`0x2321290`，漏掉了 `0x2321810`——所以此前「parse 跑通」其实漏看了这次整块拷贝。
现已补 hook（`MEMCPY2_VA`），memcpy 字段才被捕获。

## 二、变长结构更正：记录不是定宽 92B

前序文档对记录宽度说法不一，本节用 thsdk oracle 反查裁决。

### 1. 文件布局（`_tmp_000001_subtable.bin`，22192B）

```
[0, 16)      头：68 64 31 2e 30 00 = "hd1.0\0"，dc=242，flag=0x82，hs=92，fc=23
[16, 108)    内联字段表：23×4B，每条 = [tag, class, 0, width]
             tags = 1,10,13,19,22,23,54,201-204,207-210,223-230（全 class=0x70,width=4）
[108, 221)   壳段：代码标签 "!000001" + 元数据（约 113B）
[221, ...)   记录体：第一条从 counter=132477534 起
```

> 注意：STEP1 §二.0 称记录数据起点为「相对 region 偏移 205」，那是从
> `000001_record_region.bin`（22176B，切记录区产物）算的；本文从
> `_tmp_000001_subtable.bin`（22192B，含完整头）算起是 221。两者是同一记录体的
> 不同切片基准，不矛盾。

### 2. 记录是变长的（裁决 STEP1「定宽 92B」说法）

用 thsdk 的 dt13（累计成交量，单调递增）作锚点重建 241 条记录边界：

```
有效记录数：240（1 条缺失）
相邻记录步长分布：89×3，90×63，91×90，92×82（另 182×1 = 跳过 1 条）
众数步长：91B（90 条），不是 92B
```

**步长在 89–92B 之间真实变化，记录是变长的。** 这与 STEP1 §二.1「这是固定 92B 宽
记录」的说法**冲突**——STEP1 把 full/low2 计数（full=225/low2=16，本调查复现为
full=225/low2=15，吻合）误读成了「定宽」。CORRECTION §一.3 已经自我指出了这个矛盾
（「同时声称定宽 92B，又报告跨度 89–92B」），本调查裁定：**变长是真实的，定宽 92B
应降级为「标称记录宽度 hs=92，实际物理步长 89–92B」。** `VARLEN_INVESTIGATION.md`
§个股子表「记录尾部因状态字节常见 89-92B」的描述从一开始就是对的。

### 3. full / low2 两型与 `0x1600` 省略标记（裁决「00 16 不是省略标记」说法）

记录的 dt1（bar）字段是分钟计数器（counter），存在两种形态：

- **full 记录**：完整 4 字节 counter，例 `5e 72 e5 07`（=132477534）；
- **low2 记录**：低 2 字节保留真实 counter 低位、高 2 字节被 `0x1600` 替换，
  例 `98 72 00 16`（counter 低字 = `98 72`，高字 = `00 16`）。

本样本：**full=225，low2=15**。`0x1600` 在 low2 记录的 counter 高位字处确实是省略
标记。这印证了 CORRECTION/STEP1 对 `0x1600` 的判断。**（注：一次探索曾得出「00 16
不是省略控制字、是数据巧合」的结论，那是统计口径问题——`0x1600` 只在 low2 记录的
特定槽位成片出现，不是每条记录都有，故在 mod-92 直方图上不呈尖峰，被误判为平坦。
实际它在 low2 记录的 counter 高位字位置是确定性的省略标记。）**

### 4. 满字段记录布局已坐实（idx0–4 逐字段精确对齐 oracle）

从记录体起点（idx0 @文件偏移 221）读满字段记录，用现有 `decode_ths_float` 逐字段
解码，与 thsdk oracle 精确对齐：

| 记录内偏移 | 字段 | 编码 | idx0 值 | oracle idx0 |
|-----------|------|------|---------|-------------|
| +0 | dt1（bar） | LE32 分钟计数器 | 132477534 | time=1778722200 (=counter×60−6169929840) |
| +4 | dt10（价） | THS float | 11.14 | 11.14 ✓ |
| +8 | dt13（量） | LE32 | 381200 | 381200 ✓ |
| +12 | dt19（额） | THS float | 4246568 | 4246568 ✓ |

idx0–4 全部 4 个核心字段精确对齐。**满字段记录的布局与编码已完全破译**，可直接用
`decode_ths_float` 解码。

## 三、各文档说法的裁决汇总

| 说法来源 | 说法 | 裁决 |
|----------|------|------|
| STEP1 §二.1 | 定宽 92B，非变长 | ❌ **降级**：物理步长 89–92B，变长 |
| STEP1 §二.1 | 000001 full=225/low2=16 | 🟡 接近：复现为 full=225/low2=15 |
| CORRECTION §一.3 | 跨度 89–92B，可能变长也可能 DP 误差 | ✅ 裁定：**变长真实** |
| CORRECTION §一.2/§二 | parse 只是 memcpy | ✅ 成立，且更精确：单次整块 memcpy |
| CORRECTION §一.2 | STEP2 的 esi==1 全链不在本路径 | ✅ Unicorn 实证零命中 |
| STEP2 §三 | `0x691d40` bit6 是省略机制 | ❌ 已撤回（不在 esi==2 路径） |
| VARLEN §个股子表 | 记录尾部因状态字节常见 89-92B | ✅ 从一开始就对 |
| STEP1 §三 | `0x1600` 是省略标记 | ✅ 成立（在 low2 记录 counter 高位字） |
| 一次探索 | 「00 16 不是省略控制字」 | ❌ 统计口径误判，实际是省略标记 |

## 四、当前能力与剩余缺口（更新）

**已确证可做：**
1. parse 执行路径（esi==2）+ 字段解析器（type==0 单次 memcpy）行为，Unicorn 可复现；
2. 记录体布局：头/字段表/壳段/记录体的偏移边界；
3. 满字段记录的 dt1/10/13/19 布局与 THS float 解码，逐字段对齐 oracle。

**仍未解决：**
1. **low2 记录里被省略字段的精确恢复规则**：dt10 被省略为 0/控制字时，真值在客户端
   解码器的跨记录状态里，线上字节 + thsdk 不足以恢复（STEP2 §三.3 已证「复用前值」
   仅部分命中）。这是闭环的核心阻断项。
2. **变长步长的成因**：89/90/91/92 的差异是哪些字段被省略导致记录缩短？还是别的
   机制？（满字段=92B，步长<92 意味着确有字段被省略使记录变短——但这与「low2 只
   替换 counter 高位字、不缩短记录」的观察有张力，需进一步分析。）
3. **parse 之后的省略恢复消费者**：在虚槽 `[esi+0x38]`/`[esi+0x28]`，但追这条
   COM 双层 thunk 链代价极高（需重建对象状态 + 跨记录状态机）。

## 五、下一步建议（按代价从低到高）

### 1. 纯语料路径重建 codec（推荐，代价低）

满字段记录布局已破译、变长边界可用 dt13 锚点重建、full/low2 模型成立——**这些已
足够用纯语料分析重建一个正确的 Python codec**，不必逆向 getter 状态机：

- 用 DP 对齐（STEP1 已有算法）+ dt13 累计单调约束定位 241 条记录边界；
- full 记录逐字段解码（已验证精确对齐）；
- low2 记录：dt13/dt19 等未省略字段正常返回，dt10 等被省略字段标 `complete=False`/
  `missing_fields`（即现有 `history_timeline_omission.py` 的 fail-closed 思路，但
  要先修正其「定宽 92B 固定偏移」假设为变长）。

### 2. 破解 low2 的 dt10 恢复规则（中等代价）

需同标的成对 oracle（full 型 + low2 型）逐字段对齐，反推 dt10 省略态的恢复规则。
STEP2 §三.3 已试过「复用前值」「复用上一条 full」均部分命中，需更多样本。

### 3. 逆向 getter 状态机（高代价，原 CORRECTION §四.2 计划）

改造 harness 主动调虚槽 `[esi+0x38]`/`[esi+0x28]`，对记录缓冲设内存读 hook，
定位哪个函数首次读取被 `00 16` 替换的字节并还原。风险：COM 对象状态/参数依赖未知，
parse 后对象未必支持 getter 直接调用。

## 六、本会话改动的文件

| 文件 | 状态 | 备注 |
|------|------|------|
| `tests/emulate_chquote_parse.py` | ✅ 已改 | 加 esi==2 分支硬断言 + 字段解析插桩 + 补 hook `0x2321810` |
| `docs/investigations/..._INVESTIGATION_UPDATE.md` | ✅ 新增 | 本文，汇总证据 + 裁决矛盾 |
| `src/thspypc/codecs/history_timeline_omission.py` | ❄️ 冻结 | 未改（基于「定宽+省略」错误模型，待按 §五.1 修正） |
| 其它 emulate_*.py / 测试 / 生产解析器 | ❄️ 未改 | — |

## 七、给下一个会话的速查

1. **第一件事**：跑 `python tests/emulate_chquote_parse.py`，确认 `branch_ok: True`
   + `field_type_total: 1` + `type_counts: {0:1,...}`，复现 parse 单次 memcpy 结论。
2. **第二件事**：按 §五.1 走纯语料路径——用 dt13 锚点重建变长记录边界（步长 89–92），
   修正 `history_timeline_omission.py` 的定宽假设。
3. **不要**把 STEP1 的「定宽 92B」当真；**不要**把一次探索的「00 16 不是省略标记」
   当真（§二.3 已裁决）。
4. **不要**继续完善 STEP2 的 `0x691d40` harness（esi==2 路径零命中，已撤回）。
5. 满字段记录布局：`+0` counter、`+4` dt10(THS float)、`+8` dt13、`+12` dt19(THS float)，
   用 `decode_ths_float` 解码。
