# 个股历史分时省略型 codec —— 分支错位更正交接

> 状态：**撤回 STEP2 的解码链定位和省略机制结论**。经 Unicorn 实际执行路径
> 核验，`flag=0x0082` 当前样本不走 STEP2 定义的 `esi==1` 分支，而走 `esi==2`。
> STEP2 关于 `0x691d40` bit6、getter 状态机、下一步优先级的判断均不成立。
> 创建：2026-07-30。本文取代 STEP2 的核心结论，前序文档仅保留可复用的工具/
> 语料部分。
> 前序：[`HISTORY_TIMELINE_OMISSION_CODEC_HANDOFF.md`](HISTORY_TIMELINE_OMISSION_CODEC_HANDOFF.md)
> （攻坚计划）、[`..._STEP1_FINDINGS.md`](HISTORY_TIMELINE_OMISSION_STEP1_FINDINGS.md)
> （DP 对齐）、[`..._STEP2_RE.md`](HISTORY_TIMELINE_OMISSION_STEP2_RE.md)
> （逆向定位，**结论部分已撤回**）。

## 一、核验结论：STEP2 走错了格式分支

### 1. 当前样本实际走 `esi==2`，不是 `esi==1`

用现有 Unicorn harness（`tests/emulate_chquote_parse.py`）跟踪完整
`_tmp_000001_subtable.bin` 输入的实际执行路径：

```text
CHQuoteFile::parse 0x127c8b0
  → 版本分类 0x136c430 → 结果 esi=2
  → 0x136c390（esi==2 分支）
  → 0x136c080
  → 当前字段描述符 type=0 → 直接 memcpy
```

执行全程**未命中**以下 STEP2 声称的「记录解码全链」函数：

```text
0x136bbe0（esi==1 记录解码器）
0x136b8e0（表头/字段表解析）
0x139a6d0（核心按字段抽取器）
0x691d40（变长字段解码器）
```

**因此 STEP2 §二「已定位的记录解码全链」整张表描述的是另一个格式分支，
不是当前 `flag=0x0082` 数据路径。** 该结论需撤回。

### 2. `0x691d40` 的 bit6 不是「省略标志」

反汇编重读 `0x691d40`：

- `mask=0x40`（读变体）时，`and al,0x40; neg ecx; sbb ecx,ecx` 把累加器
  初始化为 `0xFFFFFFFF`；
- 随后 `shl ecx,7; or ecx,al` 是有符号 7-bit 变长整数的符号扩展；
- `0x139a6d0` 再把结果作为 **delta（增量）** 加到上一行字段值上。

这是「首行绝对值 + 后续有符号增量」的变长编码解码器，属于**别的分支**
（`esi==1` 路径，不是当前 `0x0082` 实际走的 `esi==2`）。STEP2 把它解释为
「字段省略」「跨记录隐藏状态」**没有汇编依据**，需撤回。

### 3. 「记录定宽 92B」与现有证据自相矛盾

STEP1 同时声称每条固定 92B，又报告相邻锚点跨度为 89–92B。这两者矛盾：

- `full/low2` 标签只表示「DP 搜到了完整 4 字节 / 低 2 字节 bar」，**不能**
  升级为「完整记录 / 省略记录」；
- 很多所谓 `full` 锚点的下一条跨度也小于 92B，说明物理记录可能本来就是
  变长的，或 DP 对齐本身不够精确。

在找到真正的记录消费者之前，DP 输出只能当「bar 候选锚点」，不能当
「记录边界」。

## 二、STEP2 中仍然成立的部分（保留）

以下不依赖走错的分支，可以复用：

1. **环境与工具**：`captures_live/hexin.loaded.bin`（RVA==文件偏移，
   `image_base=0xd50000`）、`tests/reverse_hexin_loaded.py`（dump 感知 RE
   辅助）、`.venv` 已装 `pefile/capstone/unicorn`。
2. **CHQuoteFile vtable/parse 定位**：RTTI `0x1acb2bc`、parse `0x127c8b0`、
   分类器 `0x136c430`、构造函数 `0x127c570`（写虚表 `0x281b2bc`）。
3. **Unicorn 跑通构造+parse**：`tests/emulate_chquote_parse.py` 解决了
   FS/SEH 段（映射 page 0 当 TEB），构造函数和 parse 都能执行。**parse
   确认只是容器解析——把记录字节原样 memcpy 到堆对象，不做字段恢复**。
4. **语料**：`tests/fixtures/history_timeline/` 的记录区切片 + thsdk oracle。
5. **`flag=0x0082` 有内联字段表**（23×4B 紧跟 header），已更正解析器。

## 三、当前 codec 不安全，应冻结

`src/thspypc/codecs/history_timeline_omission.py` 目前：

- 从每个候选起点固定按 `+0..+88` 读 23 字段（假定定宽 92B，但物理跨度
  89–92B，偏移可能错位）；
- 把任意字段高字 `==0x1600` 当省略（误判源）；
- 用「没撞到 0x1600」定义 `complete=True`。

实测：000001 只有 16 个 `low2` 锚点，但 codec 标出 **74 条 incomplete**
（大量误伤），dt10 有 **17 点错误或缺失**。该 codec 仅被测试直接调用，
**未接入生产解析器**——保留原有的 fail-closed/partial 行为。

测试 `25 passed` 不能证明 codec 正确：测试只验证「Level2 键存在」、
dt13/dt19 允许 5 点错误，**没有 oracle 校验 dt54/dt201-230**，也没证明输入
字节消费、真实记录边界或控制状态。

**建议：冻结当前 codec 和 `0x0082` 的 23 字段对外扩展。** 不要把这些 Level2
值视为已验证结果。

## 四、修正后的下一步（优先级重排）

之前判断「getter 状态机太深、只能碰 full oracle」是错的——根因是**走错了
格式分支**。正确的第一优先级是沿实际 `esi==2` 路径重新定位。

### 1. 修正 Unicorn harness，锁定真实分支（最高优先级）

以完整 `_tmp_000001_subtable.bin` 为输入，在 harness 里增加硬断言：

```text
classifier == 2
进入 0x136c390 → 0x136c080
不得误入 0x136bbe0 / 0x136b8e0 / 0x139a6d0 / 0x691d40
```

确认 `esi==2` 分支的完整执行路径，搞清 `0x136c390`/`0x136c080` 到底怎么
处理记录（当前观察是 type=0 直接 memcpy，但需确认全部字段类型和省略态）。

### 2. 从 parse 后对象追踪真正的业务解码消费者

`CHQuoteFile::parse` 已确认只 memcpy。下一步应：

- parse 后对象在堆上（harness 已能读到 `this+0x18` 等成员指针）；
- 找到**记录读取接口**（哪个 vtable getter 或外部函数读字段值）；
- 对原始记录缓冲设 **Unicorn 内存读 hook**，定位哪个函数**首次**把异常
  dt10（被 `00 16` 替换的字节）转换成正确价格；
- 那个函数才是真正的省略恢复消费者。

### 3. 重新建立结构模型

在找到消费者前：

- DP 输出**只叫「bar 锚点」**，不叫「记录边界」「full record」；
- 核对 `dc=242`（含壳/尾行？）、`hs=92`（标称记录宽度）、两个子表边界
  与实际字节数之间的差异；
- 确认 89–92B 跨度是因为变长记录、还是 DP 对齐误差。

### 4. 找到真实函数后再做 Python 移植

同标的 full/low2 成对采集和官方客户端 23 字段 oracle 仍重要，但主要用于
**验证**，不应代替当前最急迫的「找对执行分支 + 定位消费者」。

## 五、现有文件状态清单

| 文件 | 状态 | 备注 |
|------|------|------|
| `tests/emulate_chquote_parse.py` | ✅ 可用 | 构造+parse 跑通，FS/SEH 已解；需加分支硬断言 |
| `tests/reverse_hexin_loaded.py` | ✅ 可用 | dump 感知 RE 辅助 |
| `tests/emulate_history_timeline_field.py` | ⚠️ 作废 | 模拟 `0x691d40`，但该函数不在当前分支 |
| `tests/emulate_history_timeline_decode.py` | ⚠️ 作废 | 模拟 `0x136b8e0`，同上 |
| `tests/analyze_history_timeline_records.py` | 🟡 降级 | DP 对齐可用，但输出只能当 bar 锚点 |
| `tests/analyze_history_timeline_omission.py` | ⚠️ 作废 | 基于「定宽+省略」错误模型 |
| `src/thspypc/codecs/history_timeline_omission.py` | ❌ 冻结 | 误判多，未接入生产 |
| `tests/build_history_timeline_fixtures.py` | ✅ 可用 | 切记录区 + thsdk oracle |
| `tests/fixtures/history_timeline/` | ✅ 可用 | 语料 + oracle |
| `docs/investigations/...STEP1_FINDINGS.md` | 🟡 部分 | DP 对齐有效；「定宽 92B」说法需降级 |
| `docs/investigations/...STEP2_RE.md` | ❌ 撤回 | 解码链定位和省略机制结论不成立 |
| `src/.../history_timeline_protocol.py` | ✅ 更正 | `0x0082` 走内联字段表路径（不再硬编码 6 字段） |

## 六、给下一个会话的速查

1. **第一件事**：改 `emulate_chquote_parse.py`，加 `esi==2` 硬断言，确认
   `0x136c390`→`0x136c080` 路径。
2. **第二件事**：在 parse 后的堆对象上找字段读取消费者（内存读 hook +
   vtable getter 追踪）。
3. **不要**继续完善 `0x691d40` harness 或 `history_timeline_omission.py`。
4. **不要**把 DP 的 `full/low2` 当记录类型，只当 bar 锚点。
5. thsdk oracle（`min_snapshot`）仍是 dt1/10/13/19 的语义真值；Python 3.14
   site-packages 的 thsdk 1.7.18 带 `hq.dll`。
