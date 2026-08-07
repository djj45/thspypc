# 沪市竞价 32 位离线 Harness 实施计划

> ⚠ 2026-08-07：本计划针对的「沪市 7169/7176 变长编码需 x32dbg 逆向」前提已被
> `HANDOFF_KANPAN_CAPTURE_20260805.md` §J.6bis 推翻（normalize 后沪深同构定长），
> `_parse_auction_sh` 兜底也已删除。本文仅作历史存档。

> 状态：hlib 请求链已排除；hexin CHQuoteFile 入口已由内存快照静态确认
> 创建日期：2026-07-27
> 工作分支：`feat/stock-list-full`
> 目标：在不附加、不修改 `hexin.exe` 的前提下，把 `hlib.dll` 的沪市竞价解析链搬进
> 自有 32 位进程，定位并复现“随机网络变体 → 固定 CHQuote 缓冲区”的外层归一化。

## 1. 为什么要做离线 Harness

现有六股语料已经证明，同一股票、同一历史竞价结果会由服务器随机返回 A/B/C/D/E
等多种物理编码。变体独有字节携带零省略、重复值或滚动状态，不能简单删除。

当前已知的数据分层是：

```text
socket 原始响应（A/B/C/D/E）
  → 尚未定位的外层状态流归一化
  → 固定 CHQuote 头 + 压缩记录区
  → BitRLE / 位平面转置 / 字段增量解码
  → 竞价记录
```

`CHQuoteFile` 本身读取的是固定偏移头。将原始 A/B/C 直接喂给内层 BitRLE、位平面
转置或 `CHQuoteFile` 都不能得到 thsdk 真值。因此当前唯一缺口是第一层归一化。

同花顺主程序存在严格的反调试/反注入风险。Frida 探针只能作为最后手段，不能默认在
常用账号和生产安装环境附加 `hexin.exe`。离线 Harness 的价值是：

- 调试目标是我们自己的进程，不触发主程序反调试；
- 同一份原始响应可以无限重放；
- 可以安全记录每个函数的输入、输出和状态；
- 可以使用 Visual Studio、x32dbg、Frida 或硬件观察点；
- 可以用 thsdk 语料做自动化回归，而不是人工看十六进制。

## 2. 本机二进制基线

本计划中的 RVA 只对以下本机版本有效。Harness 必须校验文件指纹，不匹配时拒绝调用
内部地址。

### 2.1 `hlib.dll`

```text
路径：C:\同花顺软件\同花顺\hlib.dll
位数：32 位
文件版本：2.3.4
大小：4,752,616 bytes
SHA-256：
07F371026341E0F9B88232274DBE4252A185C56D589CD35F50531921879550D7
首选 image base：0x10000000
```

已知 RVA：

| 作用 | RVA | 首选虚拟地址 |
|---|---:|---:|
| `CHQuoteFile` 构造函数 | `0x3e4f0` | `0x1003e4f0` |
| `CHQuoteFile` 主虚表 | `0x16bf30` | `0x1016bf30` |
| `CHQuoteFile` 解析入口（vtable `+0x14`） | `0x3ea40` | `0x1003ea40` |
| `CHQuoteFile` 记录数 getter | `0x3e910` | `0x1003e910` |
| 通用 `hd1.` 版本判断 | `0x40d10` | `0x10040d10` |
| 固定头对象方法簇 | `0x35770`~`0x35970` | `0x10035770`~`0x10035970` |
| 构造并调用 `CHQuoteFile` 的上层包装 | `0x66c90` | `0x10066c90` |
| `CHQuoteFile` 构造调用点 | `0x66cf1` | `0x10066cf1` |
| `CHQuoteFile` 解析调用点 | `0x66d42` | `0x10066d42` |
| 包装函数的直接调用点 | `0x7672d` / `0x7703a` / `0x77848` | 见 RVA |

本版本使用 VMProtect：磁盘 PE 的 `.text/.rdata/.data` 节 `SizeOfRawData=0`，代码在
`LoadLibraryExW` 后才出现在内存中。已新增
`tests/native/hlib_harness/hlib_harness.exe dump-image` 与
`tests/reverse_hlib_memory.py`，后续静态分析必须基于加载后的内存映像。

旧版 2.2.0 的 `0x3e970/0x3eec0/0x66480/0x66517` 等地址仅作为历史对照，**不得**
用于 2.3.4。对 `0x66d42` 输入的反向切片已经完成：该链路从 hlib 自己的传输包
剥掉 11 字节头后原样复制 payload，没有发现把 4214/7176 随机变体改写为固定
CHQuote 头的步骤。

### 2.2 `hexin.exe`

```text
路径：C:\同花顺软件\同花顺\hexin.exe
文件版本：2019, 4, 3, 1
产品版本：9,60,20,31
大小：17,107,232 bytes
SHA-256：
7C9EB211B93DD2CD8E291859362ADFB533B40FC5A6E5231748E195460BD2D91D
```

反调试风险集中在主程序。当前解析入口反汇编虚拟地址是 `0x167c8b0`，image base 为
`0x400000`，所以真正 RVA 是 `0x127c8b0`。2026-07-27 的任务管理器快照已提供
完整加载后映像，不需要为了确认此入口而动态附加主程序。

```text
DMP：C:\Users\23027\AppData\Local\Temp\hexin.DMP
DMP 大小：1,382,519,709 bytes
DMP SHA-256：
D16BEAFACA2A37750FFC857208D666C901D2688BC5E203A44AFFAD9AFF7F9BA3
快照中的 hexin base：0x00d50000
快照中的目标 VA：0x01fcc8b0
加载映像：captures_live\hexin.loaded.bin（47,886,336 bytes，完整覆盖）
```

加载映像中的 RTTI 名称、构造函数写虚表和三个外部虚调用共同确认：

| 作用 | RVA |
|---|---:|
| `CHQuoteFile` 构造函数 | `0x127c570` |
| `CHQuoteFile` 主虚表 | `0x1acb2bc` |
| `CHQuoteFile::parse`（vtable `+0x14`） | `0x127c8b0` |
| 固定头分类/读取 | `0x136c430` |
| 外部构造调用点 | `0x685de3` / `0xa6ab61` / `0xaa4111` |
| 对应 parse 虚调用点 | `0x685e04` / `0xa6ab82` / `0xaa412a` |

ABI 为 `thiscall parse(this, buffer, length, mode)`，由被调函数 `ret 0x0c`。入口先
调用 `0x136c430`，后者识别 `hq1.`、`hq6.`、`hd1.`、`hd1.3`、`hd3.*`、
`hd4.1` 和 `hd5.*`，并直接读取 `DWORD[+6]`、`WORD[+0xc]`、
`WORD[+0xe]` 等固定头字段。因此 `0x127c8b0` 已不是候选，但它本身也不负责把
4214/7176 网络随机头改成固定头。

### 2.3 `thsdk`

```text
源码壳：D:\code\thsdk-main
本机可运行 hq.dll：
C:\Users\23027\AppData\Local\Programs\Python\Python314\Lib\site-packages\thsdk\libs\windows\hq.dll
版本：1.7.18
大小：8,697,856 bytes
SHA-256：1480DF5AB19844A5307FA65966DE19E3CC2B4F20C057012EAF1F5985F87B6949
```

`D:\code\thsdk-main` 只有 Python API 壳，不含 `hq.dll`。thsdk 的 Go 协议与
hexin.exe 的 4214/7176 协议不同；它继续只作为业务真值来源，不作为本协议的
归一化实现来源。

## 3. 非目标

首版 Harness 不做以下事情：

- 不启动、登录或自动操作同花顺主程序；
- 不附加常用账号正在运行的 `hexin.exe`；
- 不绕过反调试、完整性校验或账号风控；
- 不直接替换生产 `_parse_auction_sh()`；
- 不把 LCS 独有字节当作可删除噪声；
- 不因单支股票、单一变体成功就宣布算法完成；
- 不盲调需要完整客户端对象状态的高层成员函数。

## 4. 计划目录与产物

建议新增：

```text
tests/native/hlib_harness/
  README.md
  hlib_harness.cpp
  hlib_layout.h
  sha256.cpp
  build_x86.cmd

captures_live/hlib_harness/
  <case>/
    raw.bin
    normalized.bin
    metadata.json
    parsed_rows.json
```

其中 `captures_live/` 下的运行产物默认不提交 Git；只提交 Harness 源码、说明和小型
无敏感合成样本。

计划中的 CLI：

```text
hlib_harness.exe fingerprint --dll <hlib.dll>
hlib_harness.exe probe-chquote --dll <hlib.dll> --input <fixed.bin>
hlib_harness.exe probe-chquote --dll <hlib.dll> --input <raw-A.bin>
hlib_harness.exe normalize --dll <hlib.dll> --input <raw.bin> --output <normalized.bin>
hlib_harness.exe decode --dll <hlib.dll> --input <normalized.bin>
```

每个命令必须输出 JSON 元数据和明确退出码，方便 Python 批量驱动。

## 5. 阶段 0：准备 MSVC x86 工具链

### 目标

生成真正的 32 位 Windows EXE，并与 MSVC x86 的 `__thiscall`、对象布局和异常处理
兼容。

### 原因

当前 `w64devkit` 只有 x64 目标库，`gcc -m32` 已实测失败。64 位 Python 和当前
64 位 thsdk `hq.dll` 也不能加载 32 位 `hlib.dll`。

### 操作

1. 安装 Visual Studio Build Tools 的“使用 C++ 的桌面开发”组件和 x86 编译工具。
2. 从 `vcvars32.bat` 或 `VsDevCmd.bat -arch=x86` 环境运行 `cl.exe`。
3. 编译一个只打印 `sizeof(void*)` 的空程序，确认输出为 `4`。
4. 编译选项首轮使用 `/Od /Zi /EHsc /W4`，禁止优化，方便单步。
5. 输出放到 `build/x86/`，不要与 x64 工具混用。

### 完成条件

```text
hlib_harness.exe 是 PE32（非 PE32+）
sizeof(void*) == 4
能在本机正常启动
```

## 6. 阶段 1：只加载 DLL 和校验指纹

### 目标

不调用任何内部函数，先稳定加载 `hlib.dll` 及其依赖。

### 操作

1. 使用 `SetDefaultDllDirectories()` 和 `AddDllDirectory()` 指向同花顺安装目录。
2. 使用 `LoadLibraryExW()` 加载 `hlib.dll`。
3. 记录实际模块基址、文件版本、大小和 SHA-256。
4. 读取上述关键 RVA 的前 16-32 字节，与计划内签名比较。
5. 所有内部地址都使用 `module_base + RVA` 计算。
6. 任何指纹或入口签名不匹配时立即退出，不“猜地址继续跑”。

### 输出

```json
{
  "architecture": "x86",
  "module_base": "0x...",
  "sha256": "...",
  "version_match": true,
  "rva_signatures_match": true
}
```

### 完成条件

连续运行 20 次均能加载、卸载，不崩溃、不生成异常线程残留。

## 7. 阶段 2：验证 `CHQuoteFile` ABI

### 目标

确认构造函数、对象大小、调用约定、参数顺序和返回码；本阶段不要求原始沪市变体
解析成功。

### 推测签名

```cpp
using Constructor = void* (__thiscall *)(void* self);
using Parse = int (__thiscall *)(
    void* self,
    const void* input,
    int input_size,
    int mode
);
```

在 `hlib + 0x66d42` 的调用现场，调用方依次压入：

```text
mode = 0
input_size
input
ECX = CHQuoteFile this
```

返回值 `0` 被上层视为成功，非零进入错误清理路径。

### 操作

1. 先分配至少 `0x40` 字节、零初始化且自然对齐的对象内存。
2. 调用 `base + 0x3e4f0` 构造函数。
3. 通过对象 vtable `+0x14` 和直接 `base + 0x3ea40` 两种方式核对入口一致性。
4. 使用一份已知合法的标准固定头 `hd1.0` 响应做正向控制。
5. 使用截断响应做错误控制，确认返回错误而不是越界。
6. 再输入沪市 A/B/C 原始响应，预期失败；失败是本阶段的正确结果。
7. 析构函数未确认前，单用例单进程执行并让操作系统回收地址空间，避免猜错析构 ABI。

### 正向样本要求

优先抓一份客户端可正常解析的标准固定头响应，不要只用空载荷合成头作为唯一正样本。
以 600276 为例，人工头部的预期布局可作为元数据检查：

```text
68 64 31 2e 30 00    # "hd1.0\0"
b5 00 00 00          # 181 条
3a 00                # 头长 58
14 00                # 行宽 20
05 00                # 字段数 5
01 30 00 04
0a 70 00 04
31 70 00 04
1b 70 00 04
21 70 00 04
```

### 完成条件

- 合法固定头正样本进入正确版本和固定头分支；
- 截断样本稳定返回错误；
- A/B/C 原始变体不能误报成功；
- 调试器中 ECX、栈参数和返回值与推测一致。

## 8. 阶段 3：建立可重复的正负样本矩阵

### 正样本

- 标准 `hd1.0\0` 固定头响应；
- 合法字段表和至少一条记录；
- 已知记录数、行宽、字段数和字段模式。

### 负样本

- A：`hd1.0 ... b4 3a 91 ...`
- B：`hd1.M0 ... a4 3a ...`
- C：`hd1.0 9b ...`
- D：`hd1.0 99 ...`
- E：`hd1.L0 ...`
- 截断 1/2、截断到字段表、随机翻转单字节；
- 长度字段超大、记录数超大、字段数超大。

### 基准语料

| 股票 | thsdk 条数 | 已知字节变体数 |
|---|---:|---:|
| 600276 | 181 | 6 |
| 600519 | 100 | 2 |
| 601318 | 161 | 3 |
| 603118 | 200 | 3 |
| 688825 | 201 | 2 |
| 688981 | 149 | 5 |

用 `tests/verify_auction_corpus.py` 生成现有启发式基线；Harness 不得改变 oracle。

## 9. 阶段 4：从 `CHQuoteFile` 输入向上反向切片

### 目标

确认 `CHQuoteFile` 的输入由谁产生，并判断 hlib 链上是否存在以下转换边界：

```text
输入：含 ServerCost / Ihd1.* 的原始网络字节
输出：hd1.0\0 + 固定记录数/头长/行宽/字段数
```

### 已知调用关系

```text
hlib + 0x7672d / 0x7703a / 0x77848
  → hlib + 0x66c90
    → hlib + 0x66cf1  构造 CHQuoteFile
    → hlib + 0x66d42  调用解析入口

三个调用者
  → hlib + 0x7d3b0   同步请求/等待调度器
    → hlib + 0x79f60 收到响应后复制 payload
      → hlib + 0x75750 把等待对象中的 payload 复制给调用者
        → hlib + 0x66c90
```

### 已完成的静态结论

1. `0x66c90` 的 `input_size` 来自 `0x19190`，即字符串对象 `+0x10`；`input`
   来自 `0x19210`，按 16 字节 SSO 阈值返回内联区或堆指针。
2. `0x7d3b0` 有 7 个直接调用点，构造的请求包为：

   ```text
   0x9e8da711 (4B)
   payload_size + 11 (4B)
   operation (2B)
   zero (1B)
   request payload
   ```

   它还负责请求登记、事件等待、超时和回调，因此是状态化传输调度器，不是内容
   归一化纯函数。
3. 收包对象的方法 `0x757a0` 返回 `frame_size - 11`，`0x75800` 返回
   `frame + 11`。分发函数 `0x7a890` 按 `frame + 8` 的 16 位类型路由。
4. 找到等待请求后，`0x79f60` 只把 `(frame + 11, frame_size - 11)` 追加到结果
   缓冲区并唤醒事件；`0x75750` 又将该缓冲区原样复制给上层。
5. 因此，从 hlib 收包分发到 `CHQuoteFile::parse` 之间没有字节重写。现有
   4214/7176 抓包变体不能被此链转换为固定头；更可能的解释是 hexin 的
   4214/7176 走另一套解析链，或者此前截取的响应边界与 hlib 的 payload 边界
   不是同一层。
6. 已扫描本机现有全部 `.pcap/.pcapng/.bin` 语料；除 hlib 内存映像中的代码常量
   外，没有任何文件包含传输 magic `11 a7 8d 9e`。当前 4214/7176 语料与这条
   hlib 请求协议不同。

### 后续静态步骤

1. 已从任务管理器 DMP 提取 `hexin.exe` 的完整加载映像，并确认
   `RVA 0x127c8b0` 的 RTTI、虚表、ABI 和三个调用方。
2. 已定位固定头分类器 `0x136c430`；它不接受现有 4214/7176 原始随机头。
3. 继续从三个调用方反向定位实际 4214 响应分发，优先跟踪输入缓冲区的最后一次
   分配/改写。`0xaa3ff0` 路径只在服务名为 `snappy` 时调用 `0xaa6a90` 解压，
   暂无证据表明它是目标正规化器。
4. 动态条件恢复后，对同一响应保存 socket、正规化器输出和 CHQuote 入口三个
   边界，逐字节比较第一个变化点。

### 排除规则

出现以下情况时不要直接拿来调用：

- `this` 指向数百字节以上、构造路径不明的对象；
- 依赖工作线程、事件、锁、TLS 或全局登录态；
- 函数同时负责发包、等待和回调；
- 输入输出通过多层虚函数回调，尚未确定实际实现；
- 需要客户端窗口、账号对象或行情连接。

`0x7d3b0` 已命中上述多项排除规则，不能加入 Harness 的 `normalize` 命令。后续
Harness 只继续承担 hlib 指纹、内存映像和 CHQuote ABI 基线验证。

## 10. 阶段 5：提取外层归一化函数

### 理想情况：纯函数

```cpp
int normalize(
    const uint8_t* raw,
    size_t raw_size,
    uint8_t* output,
    size_t* output_size
);
```

Harness 直接调用，并把输出保存为 `normalized.bin`。

### 状态函数

如果函数需要滚动状态：

1. 列出状态结构的所有读写偏移；
2. 区分常量表、每包状态、每连接状态和跨包字典；
3. 只构造被实际读取的最小字段；
4. 对 A/B/C 分别从全零状态和相同初态执行；
5. 验证同一逻辑数据最终产生同一固定头和记录区。

### 不确定函数边界时

在我们自己的 Harness 中对候选前后函数设置断点或 Frida Hook，记录：

```text
调用地址
返回地址
ECX / 栈参数
输入指针和长度
输出指针和长度
调用前后 SHA-256
前 64 字节
是否满足固定头约束
```

因为调试的是自有 Harness，不涉及 `hexin.exe` 反调试。

### 完成条件

至少一支股票的 A/B/C 原始变体经过该函数后满足：

- 版本统一为可识别的固定 `hd1.` 头；
- 记录数等于 thsdk；
- 头长、行宽、字段数合理；
- 三种输出进入同一内层解析路径；
- 输出逻辑记录完全一致。

## 11. 阶段 6：把原生算法转写为 Python

### 原则

- 先写等价、可审计版本，再优化；
- 每个读操作做边界检查；
- 不使用原始指针式“读到出错为止”；
- 把状态机、控制位方向、零填充和重复值规则显式命名；
- 保留原生测试向量：输入、归一化输出、最终记录。

建议接口：

```python
def _normalize_auction_sh_wire(body: bytes) -> bytes:
    """把 shlv2 随机外层变体还原为固定 CHQuote 缓冲区。"""
```

随后复用已经验证的：

```text
_decode_bitrle_0x13746d0
_transpose_bitplane_0x1763410
字段增量/varint 解码
```

不得继续扩展 `_parse_auction_sh()` 的时间戳扫描启发式来伪装协议已解。

## 12. 阶段 7：验收和替换生产解析器

### 必须全部满足

1. 六支股票每个逐字节唯一变体全部运行。
2. 记录数与 thsdk 完全一致。
3. 时间戳集合完全一致，无漏报、无误报。
4. 价格逐条一致。
5. dt49、dt27 等字段逐条一致。
6. 同股 A/B/C/D/E 输出完全一致。
7. 不依赖固定 3 秒节拍。
8. 截断、畸形和随机数据只返回错误，不崩溃、不超大分配。
9. `tests/verify_auction_corpus.py` 退出码为 0。
10. 现有深市竞价和其他行情解析回归不退化。

### 替换策略

通过全部验收后：

1. `parse_auction_response()` 先尝试标准固定头路径；
2. 沪市随机变体进入 `_normalize_auction_sh_wire()`；
3. 归一化结果走统一 CHQuote/记录解码；
4. 旧 `_parse_auction_sh()` 保留一个版本作为诊断 fallback；
5. 再经过一段真实交易日观测后删除 fallback。

## 13. 失败分支与回退路线

### A. `hlib.dll` 中包含完整归一化函数

当前 hlib 请求链已经排除此分支：`0x7a890 → 0x79f60 → 0x75750 → 0x66c90`
原样传递 payload。除非后续证明 socket 字节在构造 hlib frame 之前已经被另一层
改写，否则不再把 `0x7d3b0` 及其等待对象当作归一化候选。

### B. `hlib.dll` 只有固定头解析，归一化位于 `hexin.exe`

不立即附加主程序。优先：

1. 用已解包 PE 做静态交叉引用；
2. 提取纯函数到 Unicorn 或自建 x86 调用环境；
3. 对必需的导入函数做最小桩；
4. 只运行候选基本块，不启动完整客户端。

### C. 归一化依赖会话或跨包状态

1. 先确认状态是否来自同一响应的前缀；
2. 若来自此前控制帧，把完整请求周期的原始帧序列加入语料；
3. 在 Harness 中实现假 socket/回调，按原顺序重放；
4. 不连接真实账号，避免把动态实验和账号风险绑定。

### D. 只找到高层 TDS 接口

`TdsStartOfflineDebug` 等导出可能有价值，但当前已见疑似按值传递的大结构，ABI 未明。
在结构大小、字段和调用约定确认前，不直接调用。可以先用反汇编确定其所有栈读取，
再决定是否做第二套 TDS Harness。

### E. 所有离线路线都失败

最后才评估隔离环境中的最小化 Frida attach：

- 独立安装目录；
- 非常用账号或不登录；
- 先空 Hook attach/detach；
- 再只 Hook 一个解析入口；
- 不做反调试绕过；
- 一旦退出、校验失败或连接异常立即停止。

这需要单独确认风险，不属于本计划默认授权。

## 14. 实施顺序清单

```text
[x] 安装并验证 MSVC x86 工具链
[x] 创建 tests/native/hlib_harness/
[x] 实现 DLL 加载和 SHA-256/RVA fail-closed 校验
[x] 准备标准固定头正样本
[x] 验证 CHQuoteFile 构造及解析 ABI
[x] 用沪市原始响应建立预期失败基线
[x] 从 0x66d42 反向切片到 hlib 收包分发
[x] 排除 0x7d3b0 请求/等待调度器和普通 payload 复制
[x] 扫描 pcap/bin，确认 4214/7176 语料不含 hlib frame magic
[x] 从任务管理器 DMP 提取完整加载后 hexin 映像
[x] 确认 hexin CHQuoteFile 虚表、解析 ABI 和固定头字段读取
[ ] 定位 hexin.exe 的 4214/7176 实际响应分发
[ ] 找到纯转换函数或最小状态边界
[ ] Harness 输出 raw/normalized/metadata
[ ] 在自有进程中动态跟踪候选函数
[ ] 还原控制位、零省略、重复值和状态推进
[ ] 转写 _normalize_auction_sh_wire()
[ ] 跑六股全部唯一变体与 thsdk 真值
[ ] 增加畸形输入和深市回归
[ ] 全量通过后替换生产启发式解析器
```

## 15. 下一次继续时的第一批动作

1. 从 `0x685e04`、`0xa6ab82`、`0xaa412a` 三个已确认 parse 调用点继续反向切片，
   找实际承载 4214/7176 的调用方及最后一次缓冲区改写。
2. 用 `tests/reverse_hexin_minidump.py search` 复查后续 DMP 是否同时保留某一
   原始样本和 `hd1.0 + record_count` 固定头；当前 DMP 只有其他业务的固定头
   堆缓冲区，没有六股目标样本。
3. 在隔离、受信任的调试条件具备后，只采集三个边界：
   socket frame、解析器输入、`CHQuoteFile` 输入，并比较第一个变化点。
4. 为新生成的 `hlib_harness.exe` 取得组织认可的代码签名或正式策略例外，再复核
   68 记录样本的 `record_count=68`；此项不阻塞静态分析。
5. 找到真实转换边界后再新增 `normalize` 命令，并导出同一逻辑数据 A/B/C 的输出
   做逐字节比较。

不要从“继续多抓几支股票”开始。当前最高价值的新数据是：

```text
同一响应在 socket、hexin 解析入口、CHQuote 入口三个边界的精确字节快照
```
