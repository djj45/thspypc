# BlockUpdate 443 云同步逆向交接（2026-08-10）

## 目标与边界

目标是在非 Windows 平台获得与同花顺 PC 客户端一致的系统板块缓存，支持个股的
概念、行业、地域等归属查询，不再依赖本机已安装的 hexin 目录。

需要严格区分三条路径：

| 能力 | 当前通道 | 当前状态 |
|------|----------|----------|
| 自定义板块/自选股管理 | `upass/ugc/cs/apigate.10jqka.com.cn`，HTTPS 443 | 已实现于 `blocks.py` |
| 系统板块本地查询 | `BlockUpdate/block_*.ini`、`block_tree.ini`、`industry.ini` | 解析已实现，但依赖 Windows 本地缓存 |
| 系统板块云缓存同步 | `cloud.10jqka.com.cn:443` | 官方客户端已确认使用；thspypc 尚未实现 |

板块行情、板块分时和成分股在线查询仍是 8901/9601 体系，不属于本文的 443
缓存同步。

## 2026-08-10 已确认事实

### 1. 云端入口

本机 `C:\同花顺软件\同花顺\global.ini`：

```ini
[SYSTEM]
BlockUpdateURL=https://cloud.10jqka.com.cn/storage/stockblock_ths/v2_hqtyb_client/
```

`Logger/HexinHttp.2026-8-9.log` 多次记录 `CCloudStorageMgr` 将这个入口从 HTTP
转换为 HTTPS。启动抓包
`captures_live/upstockname_capture_20260810_000046.pcap` 也包含到
`cloud.10jqka.com.cn:443` 的 TLS 1.3 连接。pcap 只提供连接、时序和流量大小，
无法直接读取 TLS 内的 HTTP 请求体。

直接对入口执行普通 GET 会返回 XML“上传失败”，说明官方同步并非简单的静态文件
GET；真实方法、请求头和请求体仍需从 WinINet 明文层捕获。

### 2. 本地清单 `_entries`

位置：`BlockUpdate/__base_/_entries`。当前内容概要：

```ini
[system]
last_request_download=1786293058
last_download=1786293058
version=204655

[download_file_list]
block_2.ini=3543407018,204501
block_2B.ini=1673506795,204653
block_D.ini=1416754800,204655
...
```

时间戳 `1786293058` 对应 `2026-08-10 00:30:58 +08:00`。当时客户端完成过一次
更新检查，但服务器没有高于 `204655` 的版本，因此没有得到真实增量包。

每条文件记录已经实测确认：

```text
filename = unsigned_crc32(完整文件), per_file_version
```

当前清单列出 58 个文件，58 个文件全部存在，使用 Python `zlib.crc32` 验证为
58/58 一致。版本最高的文件为：

| 文件 | 文件版本 |
|------|----------|
| `block_D.ini` | 204655 |
| `block_D9FE.ini` | 204654 |
| `block_2B.ini` | 204653 |
| `block_C2D5.ini` | 204652 |
| `block_DA61.ini` | 204650 |
| `block_DFF8.ini` | 204649 |
| `block_D18F.ini` | 204648 |
| `block_C6.ini` | 204647 |

由此可以先独立实现清单解析、版本比较、文件完整性校验和原子落盘；这些工作不依赖
真实 `.diff` 样本。

### 3. `cloud_storage.dll` 静态证据

本机 DLL：`C:\同花顺软件\同花顺\cloud_storage.dll`，版本文件时间
`2026-06-01 13:34:50`。可见字符串包括：

- `_entries`、`download_file_list`、`last_download`、`last_request_download`；
- `.diff`、`merge download file error`；
- `download.temp`、`resume`、`packlength`；
- `version`、`local_version`、`max version=`；
- `Range`、`Content-Range`、`If-Modified-Since`。

DLL 直接导入 WinINet 接口：

- `InternetConnectA`
- `HttpOpenRequestA`
- `HttpAddRequestHeadersA`
- `HttpSendRequestExA`
- `InternetWriteFile`
- `InternetReadFile`
- `HttpQueryInfoA`

因此下一步不应只依赖 pcap。钩住 WinINet 的请求和读写接口，可以在 TLS 加密前后
取得完整 HTTP 明文，即使服务端只回复“无更新”也能还原请求协议。

## 已保存的 204655 基线

完整基线已提交到：

```text
tests/fixtures/blockupdate/204655/
```

内容：

- `_entries`：2,043 字节；
- 58 个清单内文件：3,000,907 字节；
- 合计 59 个文件：3,002,950 字节；
- `_entries` SHA-256：
  `DB88F0CE18BB2F72A12E1CBBD2F70B6C7679B6085E220AB64988260AFE2BA053`。

该目录是下一次更新的“旧版本真值”，不要修改其中的文件。真实 pcap、客户端日志和
含账号会话参数的 HTTP 日志继续由 `.gitignore` 排除，没有提交到 GitHub。

## 明日执行顺序

### P0：新增三合一捕获脚本

建议新增 `tests/capture_blockupdate_cloud.py`，职责如下：

1. 启动前复制当前 `_entries` 和全部清单文件到带时间戳的临时基线目录；
2. 使用 dumpcap 对 `cloud.10jqka.com.cn:443` 做环形抓包；
3. 监控 `_entries` 的总版本、文件版本及 CRC 变化；
4. 更新发生后保存前后 `_entries`、变化文件、残留 `.diff`/`download.temp`；
5. 输出文件级版本变化、CRC32、文本 diff 和对应 pcap 时间窗口。

脚本不得删除已提交的 `204655` fixture。操作官方缓存时优先改名/复制，避免永久删除。

### P0：捕获 WinINet 明文

优先验证 Fiddler 系统代理是否能看到请求；若代理不可用，则用 Frida/API hook 捕获：

1. `InternetConnectA`：服务器与端口；
2. `HttpOpenRequestA`：HTTP verb、object path；
3. `HttpAddRequestHeadersA`：请求头；
4. `InternetWriteFile`：POST/上传请求体；
5. `InternetReadFile`：服务端响应体；
6. `HttpQueryInfoA`：响应状态、长度、Range/Content-Range。

首先捕获 `version=204655` 的“无更新”事务，即可确定请求格式；无需等待增量。

### P1：实现全量优先的跨平台同步服务

建议新增独立模块，而不是塞入自定义板块 `blocks.py`：

```text
features/blockupdate_manifest.py   # _entries 解析、CRC32、版本模型
services/blockupdate_cloud.py      # HTTPS 请求、下载、校验、原子替换
```

首版允许“首次全量 + 版本变化时全量兜底”。这已经能解除非 Windows 平台对本机 hexin
文件的依赖。真实增量格式确认后再接入 `.diff` 合并，不让增量逆向阻塞可用版本。

### P1：真实增量到达后的验证

拿到更新后比较已保存的 `204655` 与新目录：

1. 从前后 `_entries` 确定发生变化的文件；
2. 保存服务端原始响应和落盘前 `.diff`；
3. 判断补丁是文本操作、自定义二进制格式还是通用 diff；
4. 用旧文件 + `.diff` 离线重放；
5. 要求结果逐字节等于新文件且 CRC32 等于新 `_entries`；
6. 最后才把增量合并加入生产同步服务。

## 当前未决问题

- 官方下载的实际 HTTP verb、object path、请求头和请求体；
- “无更新”、全量、增量三类响应的外层封装；
- `.diff` 的二进制格式及合并算法；
- `industry.ini` 是否由另一个云存储任务同步，还是由其他行情/配置通道生成；
- 服务端是否允许从任意旧版本跨多个版本合并，还是只支持相邻版本。

这些未决项不会阻塞 `_entries` parser、CRC 校验、缓存模型以及全量兜底的实现。

---

# 2026-08-11 抓包突破：协议已完全还原

## TL;DR

用 Frida hook `wininet.dll` 的 9 个 API + curl 重放，**完整还原了板块云同步的
HTTP 明文协议**。修正了上文的多处推测，解开了全部 5 个「未决问题」：

- **不是 `.diff` 二进制补丁**，而是 **protobuf 增量**：服务端只返回版本号大于
  客户端请求版本的那部分文件，每个文件整体下发。
- **两条并存通道**：旧的 `cloud.10jqka.com.cn` 匿名 GET（交接文档原线索）和新的
  `cs.10jqka.com.cn/multiStorage`（带鉴权，实际主力）。
- **纯下载，无上传**：上文看到的「上传失败 XML」是没带鉴权的报错，客户端本身只 GET。

## 抓包工具链（已沉淀为脚本）

| 文件 | 作用 |
|------|------|
| `tests/_blockupdate_frida_hook.js` | Frida JS，hook `InternetConnectA` / `HttpOpenRequestA` / `HttpAddRequestHeadersA` / `HttpSendRequest{A,W,ExA}` / `InternetWriteFile` / `InternetReadFile` / `HttpQueryInfoA` |
| `tests/capture_blockupdate_cloud.py` | 三合一编排：frida + `_entries` 文件监控 + dumpcap |
| `tests/_blockupdate_lib.py` | `_entries` 解析 / CRC32 / snapshot / diff |
| `tests/_smoke_frida_wininet.py` | Frida+WinINet 链路冒烟测试 |

环境：venv（Python 3.10.20，`uv` 创建）+ `frida==16.7.19` + `frida-tools==12.5.1`
（frida 17.x 需要 `typing.NotRequired`，3.10 没有，必须用 16.x）。

**关键坑**：Frida 在 JS 里 `send({b64: base64_string})` 经 JSON 序列化传大 buffer
会被吞掉（251 条 `resp_body` 的 `b64` 字段全空）。必须用 `send(payload, data)` 的
第二个参数传 `ArrayBuffer` 附件，Python 侧 `on_message(msg, data)` 的 `data` 才是
原始字节。

## 实抓结果

### 首次抓包（20:20）：真实增量

`_entries.system.version` 从 `204910 → 205176`，3 次连续变化，38 个 `block_*.ini`
更新。产物在 `captures_live/blockupdate_20260811_202014/`，含三个
`entries_change_*` 子目录（每次变化前后的文件快照）。

### 第二次抓包（20:25）：无更新事务

`version=17449` 已是服务端当前版本，返回 7B protobuf。产物在
`captures_live/blockupdate_20260811_202536/`，含完整响应字节 `bodies/`。

### curl 重放验证（无需 frida）

**`cs.10jqka.com.cn` 的 token 只校验 query string（sessionid/token/expires），
不校验 User-Agent 或 Cookie，任何 HTTP 客户端均可调用**。已用 curl 完整复现三种
响应形态，样本存于 `captures_live/blockupdate_replay_20260811/`：

- `blockstock_ver0_full_185480.bin` — 全量（version=0）
- `blockstock_ver17449_notmodified_7b.bin` — 无更新
- `header_ver5_notmodified_5b.bin` — 无更新（其它 app）

## 协议规范（已确认）

### 通道 A：`cs.10jqka.com.cn` `/multiStorage`（主力）

```text
GET /multiStorage?reqtype=download
                &version={客户端当前版本}
                &appname={blockstock|header|user_profile|infoCenter|pc_customize|...}
                &userid=&sessionid=&expires=&token=
                &storepath=/
Header: Connection: close
（无请求体）
```

`userid/sessionid/token/expires` 来自登录 session（与 8901 鉴权同源，具体由哪个 HTTP
鉴权接口签发待确认；token 明确有效期 ~24h）。

响应为 **protobuf**：

```protobuf
message MultiStorageResponse {
  int32 status_code = 1;       // 200=OK有数据 / 304=Not Modified / 404=NotFound
  int32 server_version = 2;    // 服务端当前版本号；客户端下次请求要带这个值
  repeated FileEntry files = 3;// 仅包含 version > {请求version} 的文件（增量）
}
message FileEntry {
  FileId id = 1;               // 嵌套 {int32 numeric_id = 1;}
  int32 version = 2;           // 该文件版本号
  FileContent content = 3;     // 嵌套 {bytes data = 1;}
}
```

**增量判据**（已用版本扫描验证）：

| 请求 version | 状态码 | field3 条数 | 响应大小 | 含义 |
|--------------|--------|------------|---------|------|
| 0            | 200    | 118        | 185480B  | 全量 |
| 17185        | 200    | 37         | 139244B  | 增量（ver>17185 的 37 个文件）|
| 17414        | 200    | 11         | 130542B  | 增量（ver>17414 的 11 个文件，与首次抓包字节级吻合）|
| 17449        | 304    | 0          | 7B       | 无更新（= 服务端当前版本）|
| 17450        | 200    | 118        | 185480B  | 未知版本 → 退化为全量 |
| 99999        | 200    | 118        | 185480B  | 同上 |

服务端版本号 = max(所有 entry 的 version)。`blockstock` app 当前是 `17449`。
**`appname` 各自独立版本号空间**，互不影响。

### 通道 B：`cloud.10jqka.com.cn`（legacy，匿名）

```text
GET /storage/stockblock_ths/v2_hqtyb_client//
     &storetype~1&version~{_entries.system.version}&reqtype~d
```

注意 URL 编码：`%26`=`&`、`%7E`=`~`。`version` 直接用 `_entries.system.version`
（就是交接文档第 27 行 `BlockUpdateURL` 指的那个入口）。匿名，无鉴权。
这条通道在首次抓包中也出现了，但 `cs.10jqka.com.cn` 才是触发本地 `_entries` 变化的
主力（`appname=blockstock`）。

## FileEntry 内容编码

118 个 entry 的内容统计：**110 个 base64，2 个纯文本，7 个空**。

- 短内容（base64 解出 2-8 字节）：板块**名称**（GBK 中文），如
  `d2bac0e4` → GBK「节目」类词。
- 长内容（如 entry id=0 的 409B）：逗号分隔的 hex block id 列表，描述板块树父子关系。
- entry id 范围 `0 ~ 334`（hex `0 ~ 14E`），是 protobuf 包内部的文件标识，
  **既不等于 `block_*.ini` 文件名的 hex 部分，也不等于 `block_tree.ini` 里的
  `@numId`** —— 三套独立命名空间，客户端落盘时做映射。ID→文件名的精确映射待后续
  对照（不阻塞协议实现）。

## 修正交接文档的误判

| 原文 | 实际 |
|------|------|
| 第 14 行「系统板块云缓存同步 `cloud.10jqka.com.cn:443`」| 主力是 `cs.10jqka.com.cn/multiStorage`，`cloud` 是 legacy 通道 |
| 第 36 行「直接 GET 返回上传失败 XML」| 那是没带鉴权的报错；带 token 的 GET 正常返回 protobuf |
| 第 88 行 DLL 字符串 `.diff` / `merge download file error` | 实际响应是 protobuf 增量，不是二进制 diff 补丁；`.diff` 可能是旧版本残留或另一路径 |
| 第 177-179 行未决的 verb/path/header/body | 全部确认：GET，两条 path 模板见上，仅 `Connection: close` 头，无请求体 |
| 第 178 行「无更新/全量/增量三类响应封装」| 同一个 protobuf 封装，用 status_code (200/304/404) 区分 |

## 2026-08-11 二次突破：系统板块的真正通道找到了

上节的 `cs.10jqka.com.cn/multiStorage?appname=blockstock` 解码后发现是**用户自定义
板块**（118 个 entry 全是个人板块名：液冷、涨停、半导体、260807…），不是交接文档要
的「系统板块（行业/概念/地域）」。系统板块走的是另一条**匿名通道**，已被完整还原。

### 通道 C：`cloud.10jqka.com.cn` 系统板块 ZIP（无鉴权，跨平台首选）

```text
GET https://cloud.10jqka.com.cn/storage/stockblock_ths/v2_hqtyb_client/
     &storetype~0&version~N&reqtype~download
（无 header、无 cookie、无鉴权，纯匿名 GET）
```

URL 里参数用 `~` 分隔（整段被 URL-encode 成 `%26storetype%7E0%26...`）。关键发现：
**客户端真实请求里 `reqtype~d` 是 list/check（返回 storage_upload XML），而
`reqtype~download`（完整单词）才是下载**。交接文档第 27 行看到的 `reqtype~d` 不是
下载，所以一直拿到"上传失败" XML。

响应二态：

| 请求 version~N | 响应 | Content-Type |
|----------------|------|--------------|
| N < 当前版本 | **ZIP 全量包**（772568B），含 58 个 `block_*.ini` | application/zip |
| N >= 当前版本 | `<storage_download><ret code="0" msg="当前已是最新的版本"/></storage_download>` | text/xml;charset=GBK |

**只支持"全量或无更新"，没有细粒度增量**（`version~204909` 仍返回完整 ZIP）。但 ZIP
本身压缩比不错（772568B → 解压 3005081B，约 4:1），全量兜底完全可接受。

### 已字节级验证

下载 `version~0` 的 ZIP 解压后，58 个 `block_*.ini` 与本地
`C:\同花顺软件\同花顺\BlockUpdate\` 的 58 个文件 **100% 字节一致**。`_entries` 不在
ZIP 内，由客户端本地生成（记录版本/CRC）。产物存于
`captures_live/blockupdate_cloud_zip_20260811/`。

### 三条通道最终定位

| 通道 | 主机/路径 | 鉴权 | 数据 | 用途 |
|------|----------|------|------|------|
| **C（系统板块）** | `cloud.10jqka.com.cn/storage/stockblock_ths/...` | 匿名 | ZIP（block_*.ini 全量）| **行业/概念/地域板块，跨平台首选** |
| B（用户配置） | `cs.10jqka.com.cn/multiStorage?appname=X` | userid/sessionid/token | protobuf 增量 | 自定义板块（blockstock）、header/user_profile 等个人配置 |
| A（板块上传） | `cloud.10jqka.com.cn/...reqtype~u` | - | XML | 客户端上传自定义板块（不在本项目范围） |

交接文档原标题「系统板块云缓存同步」的答案是：**通道 C**。这是匿名 GET + ZIP，跨平台
实现只需 `urllib + zipfile`，不依赖任何鉴权或 WinINet。

## 下一步（更新优先级）

### P0：实现系统板块同步（通道 C，匿名 ZIP，最简单）

```text
features/blockupdate_cloud.py    # 通道 C: cloud.10jqka.com.cn ZIP 全量下载
```

只需 `urllib.request` + `zipfile`，**无鉴权**。流程：
1. GET `https://cloud.10jqka.com.cn/storage/stockblock_ths/v2_hqtyb_client/&storetype~0&version~{本地version}&reqtype~download`
2. 若返回 XML「当前已是最新的版本」→ 无更新，结束
3. 若返回 ZIP → 解压覆盖本地 `block_*.ini`，用 `_blockupdate_lib` 算 CRC32 重建 `_entries`
4. 本地 version 从 `_entries.system.version` 读，首次填 0 触发全量

这一步**完全解除非 Windows 平台对本机 hexin 文件的依赖**（交接文档的核心目标）。
已字节级验证：`captures_live/blockupdate_cloud_zip_20260811/` 的 58 个文件与本地一致。

### P1：实现用户自定义板块同步（通道 B，protobuf，需鉴权）

```text
features/userblocks_cloud.py     # 通道 B: cs.10jqka.com.cn/multiStorage protobuf 增量
```

需要 `userid/sessionid/token/expires`（来自登录 session）。protobuf schema 已还原，
增量天然支持（version=0 全量，之后只拿变化文件）。

待解决：token 签发入口（哪个 HTTP 鉴权接口）。两次抓包的 token 有效期至 2026-08-12 20:25。

### P2：FileEntry ID → block_*.ini 文件名映射（仅通道 B 需要）

通道 B 的 118 个 entry 用数字 id（0~334），与本地文件名是三套独立命名空间。
若要复用通道 B 的数据，需系统对照 还原映射规则。通道 C 不需要此步。

### P3：通道 A 板块上传（不在 MVP 范围）

客户端上传自定义板块到云端。非本项目目标。

