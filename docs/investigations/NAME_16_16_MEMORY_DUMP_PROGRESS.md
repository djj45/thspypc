# name_16_16 内存快照分析进展（2026-08-08）

> 状态：编码结构已确认到 `[ctrl][16B]`；token 语义尚未完全破译。
> 本次最大进展是拿到了与密文同版本的全量明文，可作为 100% 比对 oracle。

## 1. 全量明文恢复

从 `hexin_timed.dmp`（105709 版）读出解码缓冲区：

- 明文缓冲区：`0x2aa8a030`，长度 `762752 B`
- 对照 `stockname_16_0_full.txt`（`762738 B`）：逐字节一致，仅 8 个段之间多出 `\r\n`
  （文件写盘时去掉了段间空行）
- 段版本：`16_16..16_23` 的 `ConfigVer` 与磁盘文件完全一致

所以后面的解码器验证可以直接用 `captures_live/stockname_16_0_full.txt`
或内存明文做 oracle，不再局限于之前 5206 B 的首段样本。

## 2. 编码流边界

密文缓冲区 `0x3c2f4000` 的结构：

```text
...二进制前缀...
MarketCode=16\x00\r\n
[name_16_16]\r\n
<编码流第一份>
MarketCode=16\x00\r\n
[name_16_16]\r\n
<编码流第二份>
```

第一份编码流 = `name16_cipher_mem.bin[14:362580]`，长度 `362566 B`，
即 `21327 * 17 + 7`。磁盘流样本
`upstockname_new_stream46_server.bin` 中 `[name_16_16]` 之后的前 422 B
与内存流一致，之后内容不同（另一轮抓包），但 `ConfigVer` 相同。

## 3. 已确认的编码结构

前 4 个 17 字节记录：

```text
ctrl=0x00   ConfigVer=202608          -> 16B literal
ctrl=0x00   07_2552009064\r\n1         -> 16B literal
ctrl=0x00   A0001=上证指数|0           -> 16B literal
ctrl=0x83   30 30 30 31 40 73 0d 0a 31 c1 32 3d a3 c1 b9 c9
```

记录 3 解码为 20B：`00001@s\r\n1A0002=Ａ股`。

- `data[3]=0x31` 展开 `01`：回引 offset=16, len=2
- `data[9]=0xc1` 展开 `A000`：回引 offset=26, len=4

记录 4（ctrl=0xd6）起 token 非常密集，目前尝试过的假设都不能稳定对齐：

- ctrl 位掩码 + 各种位到位置映射（线性/逆序/成对）
- 1 字节 token（把不匹配字节全当回引）
- 固定 17B 记录 + token 数量由 ctrl 编码
- ctrl 低位 = 输出长度/额外长度（总量对不上 762KB）

## 4. 静态分析定位

基于 `hexin.loaded.bin`（image base `0xa50000`）：

- `upstockname` 引用：RVA `0x685ab4 / 0x68a667`
- 0x1600 报文分发：RVA `0x6865c0`、`0x68f5d0`
- 17 字节元素容器（vector<[u32][12B][u8]>）：RVA `0xa71860`、`0xa71c20`、`0xa72a40`
- `ConvertNewFormatToHDFormat` 日志：RVA `0x679000`（附近是 `{...}` 文本解析，非 17B 解码器）
- 文件名/写入：RVA `0x127b000`、`0x127ae00`，`ConfigVer=` 写入在 `0x127b60c`
- 尚未定位到真正的叶子解码函数

## 5. 下一步

1. Ghidra/IDA 对 `hexin.loaded.bin` 做函数识别，从 `0x686040 / 0x6865c0`
   向下追 17B 块解码逻辑（推荐，符合 playbook 加载镜像静态分析路线）
2. 拿到函数后优先用 Unicorn 离线模拟，而不是动态附加（playbook 第 8 节）
3. 若静态卡死，最后手段才是 x64dbg + ScyllaHide，
   在 `CreateFileW` 写 `stockname_16_0.txt` 处抓调用栈和明文缓冲
4. 纯 Python 解码器验证：`name16_cipher_mem.bin` 第一份流
   -> 应与 `stockname_16_0_full.txt` 100% 一致

## 6. 关键文件

- 密文：`captures_live/name_dump_20260808_105709/name16_cipher_mem.bin`
- 明文：`captures_live/stockname_16_0_full.txt`
- 内存明文：`hexin_timed.dmp` -> `0x2aa8a030`
- 加载镜像：`captures_live/name_dump_20260808_105155/hexin.loaded.bin`
- 磁盘流：`captures_live/upstockname_new_stream46_server.bin`
## 7. 续：段头就是普通 LZ 文本（2026-08-08 追加）

用内存明文（含段间空行）重新对齐后，确认：

- 记录边界 = 固定 17 字节，`[ctrl][16B]`，从流首 0 开始（记录 171 位于流偏移 2907 = 171*17）。
- 段头 `[name_16_17]\r\nConfigVer=...` 不是特殊结构，是**普通文本 + 回引 token**：
  - `1f` 展开 `name_16_1`（回引输出第 1 字节，距离 ~5206）
  - `e0` 展开 `ConfigVer=20260807_25`（回引输出第 14 字节，距离 ~5205）
  - `09` 展开 `95`
  - `20` 展开 `\r`（最近源距离 = 32，恰好等于 token 值，可能是短距离直接编码）
  - `45` 展开 `a2`（GBK 发字第二字节）
- 所以第一个 362566B 的编码流覆盖全部 8 段明文（含段头），762KB 明文整体就是解码目标。

### 未解点

- token 单字节如何编码 (distance, length)：长距离（~5205）远超 256，短 token（20->32）又像直接距离，规则还没定。
- ctrl 字节（如 0x5b）与 token 位置的关系仍未找到简单位掩码/计数模型。
- 下一步优先级：
  1. Ghidra/IDA 反编译 `hexin.loaded.bin`，从 `0x686040/0x6865c0` 向下找 17B 块解码函数；
  2. x64dbg + ScyllaHide 在 `CreateFileW` 写 `stockname_16_0.txt` 处抓调用栈（最后手段）；
  3. 拿到解码函数后用 Unicorn 离线模拟，再写纯 Python 解码器做 762KB 全量比对。

## 8. 续：Ghidra 静态链路定位（2026-08-08 追加）

装了 Java 21 + Ghidra 12.1.2（代理安装），把两个加载镜像按
RawBinary（RVA==文件偏移）导入，分析完成。调用链已定位：

```text
NEW_UpdateStockName 处理      hexin 0x686040
  -> 按 [u32 len][data] 切片
  -> FUN_010dced0 0x68ced0     任务分发
  -> FUN_010dc260 0x68c260     后台任务
  -> FUN_01cca720 0x127a720
  -> FUN_01cca490 0x127a490
  -> FUN_01ce57b0 0x12957b0    文本解析（=、[section]、\r\n）
       -> FUN_01ce5950          key=value 行
       -> FUN_01ce4b00          [name_16_16] 段注册
       -> FUN_01ce3c00          段对象构造（0x37B，含记录向量）
  -> 17/25 字节记录容器         hexin 0xa71xxx / 0xa74xxx 类
```

func_sdk_17.dll 里的 `0x40120` 只是响应头行解析（FUN_63570120），
真正的 name_16_16 解码器仍在 hexin.exe 链路里。

Ghidra 工程与反编译输出：
- 工程：`D:\code\test\ghidra\projraw`（hexin）、`projsdkraw`（func_sdk_17）
- 输出：`D:\code\test\ghidra\out\` 下 hexin2..hexin12 / sdk / sdk2
- 待办：继续从 `0xa72c20 / 0xa72f20 / 0xa74e60` 找 17B 块解码叶子函数，
  或直接搜索引用段对象记录向量 (+0x19) 的函数。

## 10. 续：解码必然早于 FUN_01cca490（2026-08-08 追加）

### 10.1 调用链精确化（汇编级确认）

- `FUN_010d6040`（0x686040，NEW_UpdateStockName）把响应按 `;`/`:` 切片，
  对每段 `FUN_010dced0(market, data_ptr, data_len, flags)`。
- job 字段（0x30B 对象）：`+0x20`=market id，`+0x24`=data_ptr，`+0x28`=data_len，
  `+0x2c`=flags（0x1000=diff / 0x2000=base）。
- `FUN_010dc260` 读取 job 后调用 `FUN_01cca720(market, data_ptr, data_len, flags)`。
- `FUN_01cca720`（ret 0x18 确认 6 个栈参）把 `data_ptr/data_len/flags` 原样传给
  `FUN_01cca490(this=obj, data_ptr, data_len, flags)`。
- `FUN_01cca490` 两种分支都直接把 data 交给 `FUN_01ce57b0`（文本解析）：
  - 非 diff 分支：`FUN_01ce57b0(data, len)`，失败后走本地文件 `__access` 回退。
  - diff 分支：`FUN_01ce57b0(data, len)`，`FUN_01ce52c0()!=0` 时直接返回 `0xfffffffd`。
- `FUN_01ce57b0` 会 `__mbsnbcpy` 后按 `\0` 停止；market16 码流第一个 ctrl 字节是
  `0x00`，所以**把原始 17B 码流交给它必然解析失败**。

结论：**真正的 17B 解码器不在 `FUN_01cca720 -> FUN_01cca490 -> FUN_01ce57b0` 链路上**，
而是在更早的接收/下载路径里。当前静态调用链在这条线上是断的，不是"解码在这里但没看懂"。

### 10.2 DMP 缓冲池结构（0x31c73000 / 0x31bb3000 / 0x2aa8a000）

- 原始响应节点 `0x31c73000`：payload 从 `+0x38` 开始（`ServerCost=...\r\nhd3.1...`），
  `+0x14`=0x94000（数据长度），`+0x00/+0x04` 是侵入式双向链表指针。
- 解码结果节点 `0x31bb3000` 与 `0x2aa8a000`：数据从 `+0x30` 开始，
  `+0x10`=分配页大小（0xbb000），`+0x14`=容量，`+0x24/+0x28`=明文长度
  （762738 / 762754），`+0x00/+0x04` 指向链表前后节点。
- 两个解码节点分别对应当前抓到的两份明文：
  `0x31bb3030`（762738B，与磁盘文件一致）、`0x2aa8a030`（762752B，段间多 `\r\n`）。
- 说明存在**两次完整下载/两份原始响应**（0x31c73000 与 0x3c2f4000），
  解码器至少被调用过两次；解码结果节点就是通用缓冲池节点，不是专用类。

### 10.3 oracle 精确记录边界（本轮重新核验）

以 `stockname_16_0_full.txt` 去掉开头 14B 为明文 oracle，前 6 条记录输出边界：

| 记录 | ctrl | 输入 16B | 输出区间 | 输出长度 |
|------|------|---------|---------|---------|
| rec0 | 00 | ConfigVer=202608 | 0..16 | 16 |
| rec1 | 00 | 07_2552009064\r\n1 | 16..32 | 16 |
| rec2 | 00 | A0001=上证指数\|0 | 32..48 | 16 |
| rec3 | 83 | 0001@s\r\n1 c1 2=Ａ股 | 48..68 | 20 |
| rec4 | d6 | b8 75 ca 97 @s\r " 3=Ｂ股 f3 d6 | 68..105 | 37 |
| rec5 | 28 | @s\r 05 B0001=工业 | 105..122 | 17 |

rec4 的一个自洽 parse：tokens 0..7 与 14..15（展开 1/2/4/4/1/1/1/6 + 7/4），
literals 8..13（`33 3d a3 c2 b9 c9`）。rec3/rec5 可凑成 `[literal][token]` 偶对结构，
但 rec4 不满足，说明偶对只是巧合，不是统一规则。

已排除的简单模型（本轮重跑确认）：
- ctrl 位掩码 1:1 映射到 16 个位置（8 位装不下，且 rec3/rec4/rec5 均对不上）；
- token 字节直接编码 (dist,len) 的常见位分配（高 3/低 5、高 4/低 4、`>>3` 等全不成立）；
- 256 项静态 (dist,len) 表（hexin 与 func_sdk_17 均未扫到匹配表）；
- 普通 LZ77 任意回引的 DP：前 14 条记录内就会无解（说明存在非回引语义，或边界假设错）。

### 10.4 下一步（按优先级）

1. **动态断点**（最快突破口）：x32dbg + ScyllaHide
   - `FUN_010dced0`（0x68ced0）入口：抓 job 里 data_ptr/len，确认装的是原始码流。
   - `FUN_01cca490`（0x127a490）入口：抓 param_2/param_3，确认是原始码流还是明文。
   - 若 `FUN_01cca490` 拿到的是明文：沿 `0x68ced0` 之前找解码函数；
     若拿到原始码流：说明完整下载走另一条消息路径，需在 `upstockname` 之外继续找。
   - 备选：`CreateFileW` 命中 `stockname_16_0.txt` 时抓调用栈（playbook 已有流程）。
2. 静态继续：反编译 `FUN_010d00c0`（0x6800c0，0x1c 消息分支也调 `FUN_010dced0`），
   确认是否有第二条调用链把解码后的明文送进来。
3. oracle 侧：用 10.3 的边界解出前 50 条记录真 token 表，拟合 `token_byte -> (dist,len)`；
   工具已存到 `tests/name16_oracle_tool.py`。


## 11. 动态断点验证：解码发生在消息回调之前（2026-08-08 19:07 追加）

用 x32dbg headless + ScyllaHide（VMProtect profile，BreakOnTLS=0）附加运行中的 hexin.exe，
登录后抓到了完整链路。这是首次在严格反调试下成功动态附加，确认：

```text
网络/对象构造层（解码应在此层）
  -> FUN_018f55c0  0xea55c0   读取 obj[0xb] 的 0x1600 帧（已是明文帧）
  -> FUN_018efbe0  0xe9fbe0   拆 0x1600 帧
  -> FUN_018efe00  0xe9fe00   调 FUN_010d00c0
  -> FUN_010d00c0  0x6800c0   MSG0C0：data 已是 [name_16_16] 明文
  -> FUN_010dced0  0x68ced0   JOB：data/len 已是明文（0xBA382 / 0xBA372）
  -> FUN_01cca490  0x127a490  arg1 明文，arg2=0xBA382/0xBA372
  -> FUN_01ce57b0  0x12957b0  文本解析
  -> CreateFileW stockname_16_0.txt
```

关键观测（第二轮 capture2）：
- `MSG0C0 ret=013AFF53 a1=375A6020 a2=375A6049 a3=BA382 head=[name_16_16]...`
  ret RVA=0xe9ff53，即从 `FUN_018efe00` 调进来，data 已是明文。
- 同一时刻 `FBE0/FE00` 的 0x1600 帧头在 `0x375A6020`，帧长约 `0xBA3AB`，
  说明 `FUN_018f55c0` 拿到的 obj 内帧就是明文帧，不是密文。
- `FUN_010c9000`（0x679000，`ConvertNewFormatToHDFormat`）本次 name16 路径 **没有命中**；
  它只处理 `{` 开头的 new-format 帧（`FUN_01a9a730` 就是检查首字节是否 `{`），不是 17B 解码器。

结论：真正的 17B 解码在 `FUN_018f55c0` 之前，即网络接收层构造 `obj[0xb]` 帧缓冲之前。
下一步优先找这个 push 对象（`*obj==4`、`obj[5]==4`、`obj[0xb]=帧指针`）的构造/写入点；
动态日志和断点脚本已归档：
- `captures_live/name_dynamic_20260808_1907/headless1_stdout.txt`
- `captures_live/name_dynamic_20260808_1907/headless2_stdout.txt`
- 脚本 `D:\software\x64dbg\name16_headless_capture2.txt`
- 驱动 `tests/headless_name16_capture.py`

## 12. 动态调用栈：从 socket 收到数据到 push 对象构造（2026-08-08 19:49 追加）

第三轮动态抓到 25 帧调用栈，已经可以完整串起接收路径：

```text
CDataSocket::OnReceive         FUN_018e6550  0xe96550
  -> CSession::OnSocketReceiveData FUN_018f27f0 0xea27f0
  -> FUN_018f2620               0xea2620     按块喂给 session 虚函数
  -> FUN_018f2a80               0xea2a80     分配 0x30 push 对象，*obj=4
  -> FUN_018efd40               0xe9fd40     消息回调
  -> FUN_018f55c0               0xea55c0     读 obj[0xb] 帧缓冲（已是明文帧）
  -> FUN_018efbe0               0xe9fbe0     拆 0x1600 帧
  -> FUN_018efe00               0xe9fe00     调 FUN_010d00c0
  -> FUN_010d00c0               0x6800c0     data 已是 [name_16_16] 明文
```

session vtable 实测：
- vtable 指针 `0x1a85e4`
- `+0x10` 虚函数 = `FUN_018f4e00`（RVA `0xea4e00`），帧组装器
- `FUN_018f4e00` 组装完整帧后调用 `FUN_018f5100`（`0xea5100`）
- `FUN_018f5100` 调用 `FUN_019c4260`（RVA `0xf74260`）

`FUN_019c4260` 是疑似 17B 块解码器：
- 16 位滚动哈希表（0x10000 项，按最近 3 字节的 `(((a<<4)^b)<<7)^c` 索引）
- 位流控制：0 表示复制 2 个字面字节；1 表示从哈希表回引，后续控制位决定 1/2/4/8/... 长度
- 长匹配用 `0xff` 扩展 RLE
- 输出长度来自输入前 4 字节（`FUN_019c6900` 按 little-endian 读）

遗留问题：
- 动态抓到的 name16 `F5100` 输入是 `00 17 48 28 00 16 FF 0F ... MarketCode=16...`，
  前 4 字节按 LE 读会得到超大长度，所以 `FUN_019c4260` 在 name16 帧上可能直接失败返回，
  真正的 17B 解码可能发生在更早的 HTTP 下载路径，或 `FUN_019c4260` 的输入需要去掉帧头。
- 下一步：在 `FUN_019c4260` 的调用者 `FUN_019c4a03`（文件解压路径）和 HTTP 下载回调上继续抓输入，
  确认压缩 payload 的实际首 4 字节；拿到后可直接把 `FUN_019c4260` 算法翻译成纯 Python。

本轮日志已归档：
- `captures_live/name_dynamic_20260808_1949/headless5_stdout.txt`
- `captures_live/name_dynamic_20260808_1949/headless3_stack_stdout.txt`

## 13. 结论：name_16_16 就是 cmd=0x0a 外层 LZ，17B 记录是压缩源（2026-08-08）

### 13.1 关键结论

name_16_16 的“17B 块状编码”不是第二层编码，而是外层 LZ 压缩流的字节分布。
真正的解码器就是已移植的 `normalize_8901_response`（hexin.exe RVA 0xf74260）。

- 原始响应帧体以 `0x0a` 开头：`0x0a` + BE32 输出长度 + `0x1600` 帧头 +
  `MarketCode=16\x00\r\n` + `[name_16_16]\r\n` + 压缩流。
- `normalize_8901_response(body)` 解出的正是带 0x1600 头的明文帧。
- 磁盘文件 `stockname_16_0_full.txt` = 解压输出去掉 0x1600 头 + `MarketCode=16\r\n`，
  并把 8 个段之间的 `\r\n\r\n` 压成 `\r\n`。

### 13.2 100% 验证

用 10:57 同版本内存密文重建完整压缩源（固定头 + `MarketCode=16\x00\r\n` +
`name16_cipher_mem.bin`，长度字段 0x00174828），`normalize_8901_response` 解压后
去掉段间空行，与 `stockname_16_0_full.txt` **逐字节 0 差异**（前 762738 B）。

Unicorn 原生模拟同一镜像的 `0xf74260`（base 0xa50000，malloc/free/memcpy RVA
0x15e2ba2/0x15e10d9/0x15d1290），与 Python 端口逐字节对比：10:38 帧只在输出尾
1602587 处有填充差异，正文一致。10:38 与 10:57 在解压后第 652 字节起内容不同，
是两轮抓包快照不同，不是解码 bug。

### 13.3 活网抓包

2026-08-08 10:38 冷启动 pcap 中包含真实 `name_16_16` 响应（362,635B 压缩帧），
`decode_name_frame` 解出 1,155 条、`skipped=[]`；765B 的 `name_168_16` 帧也解出
13 条。

### 13.4 代码落地

- `decode_name_frame` 先调 `normalize_8901_response`，再按 `[name_16_*]` 段解析
  GBK 文本；`name_16_16` 不再被当作未解块状段跳过。
- 验证：10:57 重建帧可解出 `600000=浦发银行`、`1A0001=上证指数`，`skipped=[]`，
  names > 20000。
- 相关测试：`tests/test_stock_name_protocol.py::test_captured_a_share_compressed_stream_decodes_names`。

### 13.5 两次冷启动对比（21:43 / 21:44）

- 正常启动：0x001c 帧带 16_* 的 ConfigVer，服务器不回 `name_16_16`。
- 删文件启动：0x001c 帧 `StockNameVer=;;`，服务器回 515,526B `name_16_16`，
  解出 33,619 条。
- `build_stock_name_ver_frame()` 逐字节复刻删文件启动的请求帧（有回归测试）。

活网重放（成功）：新开裸 socket 连 `shlv2.123ths.com`（122.9.115.201），用同一
passport 登录（VerifyCode=0），重放删缓存引导（每帧 `encode_frame(body) + b"\n"`），
约 50ms 后回 515,526B `name_16_16`，解出 33,619 条。可复现脚本：
`tests/probe_stockname_full.py`。

### 13.6 域名映射与跨平台实现

| 账号 | A股名称组 | 域名 | 触发帧 | 响应 |
|---|---|---|---|---|
| level2 | 16;144;208 (pageid 5716) | `shlv2.123ths.com` | `MarketCode=16;144;208; StockNameVer=;;` | 515,526B -> 33,619 条 |
| 普通 | 32;208 (pageid 392) | `main.123ths.com` | `MarketCode=32;208; StockNameVer=;;` | 860,896B -> 57,135 条 |

其他市场组：`szlv2`（32）、`fu4`（96/128/88/216/48）、`hkus`（176/112、168/184/200）、
`ifindhq`（120/104）、`fu2`（64）、`usotc`（UNS/UHI），均为 `*.123ths.com:8901`。

实现：`features/stock_name_bootstrap.py` 用结构化模板 + 构造器生成引导帧（`stock_name_bootstrap_data.json`），不再内嵌 hex；
`services/stock_name.py::download_full_stock_names` 开新 socket 登录、重放引导、
发触发帧并解码；`ServiceFacade.fetch_stock_names_full()` 用当前 passport 接入；
已删除 `load_hexin_names`（Windows stockname 文件读取）。

缓存管理：全量下载后把每段 ConfigVer + 名称存到 `~/.thspypc/stockname/`，下次上报
缓存 ConfigVer；服务器静默时直接用缓存；增量响应合并名称并按段合并 ConfigVer。

### 13.7 旧版本实验（22:22）

把本地 stockname 换成 2026-03-06 历史文件冷启动，客户端上报真实旧 ConfigVer
（16_*、144_* 为 `20260306_...`），服务器回 451,275B `name_16_16`。用 222248
引导模板重放可稳定复现；用编造的旧版本（`20200101_1`）服务器不回。缓存策略：
上报缓存 ConfigVer，收到分段增量时合并名称并逐段更新 ConfigVer，不整表覆盖。
