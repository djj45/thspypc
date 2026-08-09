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
