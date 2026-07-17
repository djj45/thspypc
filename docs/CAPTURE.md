# 同花顺抓包指南

同花顺 PC 远航版（hexin）流量抓包操作手册。每次需要抓协议时查这里。

## 工具位置

| 项 | 路径 |
|----|------|
| **Wireshark 启动器** | `D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\WiresharkPortable64.exe` |
| **tshark（命令行解析）** | `...\App\Wireshark\tshark.exe` |
| **dumpcap（命令行抓包）** | `...\App\Wireshark\dumpcap.exe` |

> 完整工具链（editcap/mergecap/capinfos 等）都在 `...\App\Wireshark\` 下。
> 路径较长，建议设环境变量或用项目脚本（已内置绝对路径）。

下方 `WS` 代指：
```
D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark
```

## 网卡选择

用 `tshark -D` 查看当前网卡列表。**网卡编号会随 USB/虚拟网卡增减而变化，每次抓包前务必重新确认。**

常见网卡：
- **WLAN（物理 WiFi）**——同花顺走外网时用这个
- **以太网**——有线网络时用
- **本地连接* N**——虚拟网卡，通常忽略

快速确认哪个网卡有同花顺流量：
```bash
"$WS/tshark.exe" -D                    # 列出所有网卡
# 然后 ping 一下同花顺服务器，看哪个网卡有包
ping 106.14.65.90                      # 9601 短线精灵服务器
```

项目历史抓包用过 `WLAN（编号 4）`，但**不要假设编号固定**。

## 同花顺网络架构

| 端口 | 用途 | 协议特征 |
|------|------|---------|
| **8901** | 主行情/鉴权/心跳 | FD FD FD FD 帧头 + `\x09` + GBK 文本 |
| **9601** | 短线精灵（历史 qurealorder + 实时推送 pushrealorder） | 同上帧格式 |

服务器：
- 8901: `122.9.202.190` 等（多 IP 自动重试）
- 9601: `106.14.65.90`

**抓包过滤**（BPF，dumpcap/tshark 用）：
```
tcp port 8901 or tcp port 9601
```

## 常见抓包场景

### 场景 1：抓短线精灵的阈值设置请求（当前任务）

**目的**：你在同花顺客户端改了短线精灵的异动阈值（大于多少手/百万），需要抓到改完后的 `qurealorder` 请求里的 `datatype=` 字段。

**操作步骤**：
1. 打开同花顺，登录，**先不要动短线精灵设置**
2. 运行抓包（见下方命令）
3. 在同花顺里：**打开短线精灵 → 改阈值设置 → 确认保存 → 刷新一下列表**
4. 等 10~15 秒，停止抓包（Ctrl+C 或等自动结束）

**抓包命令**：
```bash
cd D:/code/ths_takehome/thspypc
WS="D:/software/Wireshark_4.6.7_Portable/Wireshark/WiresharkPortable64/App/Wireshark"

# 先确认网卡
"$WS/tshark.exe" -D

# 抓 30 秒（把 N 换成你确认的 WLAN 编号）
"$WS/dumpcap.exe" -i N -f "tcp port 9601" -w captures_live/dxjl_settings.pcap -a duration:30
```

**提取 datatype**（抓完后）：
```bash
# 从 pcap 里提取所有含 datatype 的请求
"$WS/tshark.exe" -r captures_live/dxjl_settings.pcap \
  -Y "tcp.port==9601 and tcp.payload" \
  -T fields -e tcp.payload | tr -d ',' | tr ':' ' ' | \
  while read hex; do echo "$hex" | xxd -r -p 2>/dev/null | grep -a "datatype="; done
```
> 上面命令复杂，更简单的方式是用项目脚本（见下"项目脚本"）。

**对比方法**：抓到的 `datatype=` 和当前默认值对比：
```
当前默认（src/thspypc/protocol.py DXJL_DATATYPE）：
1074269398{19[10000~-]|17[5000000~-]},1074269399{19[10000~-]|17[5000000~-]},1074269401,1074269403
```
- `19[10000~-]` = 成交手数 ≥ 1万手（字段19=成交手数，单位=手）
- `17[5000000~-]` = 成交金额 ≥ 500万元（字段17=成交金额，单位=元）
- `|` = OR（满足任一即可，实测确认）
- 改阈值后这些数字会变（如 2万手→`19[20000~-]`）；新增异动类别会有新的类别 ID。
- 类别 ID 规则：`组前缀 | 异动字节`（见 protocol.py ANOMALY_GROUP_PREFIX），
  如 `0x40080cd6` = 大笔买入，改异动字节即换类型。

### 场景 2：抓登录/鉴权流程（8901）

**目的**：看 Passport64 生成、login 响应、VerifyCode 等。

```bash
# 关闭同花顺 → 开始抓包 → 打开同花顺登录 → 90秒后结束
"$WS/dumpcap.exe" -i N -f "tcp port 8901 or tcp port 9601" \
  -w captures_live/hexin_login.pcap -a duration:90
```

项目脚本：`py tests/capture_hexin_start.py`（自动抓+分析启动序列）。

### 场景 3：抓实时推送（pushrealorder）

**目的**：采集 9601 的实时异动推送帧，逆向数值编码。

**必须盘中（9:30-15:00）**，非交易时段无推送。

```bash
# 订阅后会持续收到 pushrealorder 帧
"$WS/dumpcap.exe" -i N -f "tcp port 9601" \
  -w captures_live/push.pcap -a duration:120
```
> 更推荐用 `py tests/collect_push_samples.py`（直接解析存 jsonl，不用 pcap）。

## 用项目脚本抓包（推荐）

项目内置了 Wireshark 绝对路径，不用手敲：

| 脚本 | 用途 | 依赖 |
|------|------|------|
| `tests/capture_hexin_start.py` | 抓启动序列（login + subreal + 推送），自动分析 | dumpcap + tshark |
| `tests/collect_push_samples.py` | 采集推送+历史对照样本（盘中） | 账号（.env） |

`capture_hexin_start.py` 里网卡编号硬编码为 `-i 4`（WLAN），**如果网卡变了要改这行**（脚本第 34 行）。

## pcap 文件位置

抓包产物统一放 `captures_live/`（已 gitignore）：
```
D:\code\ths_takehome\thspypc\captures_live\
```

如果目录不存在，脚本会自动创建。

## 常见问题

**Q: 抓不到包？**
- 检查网卡编号（`tshark -D`），WLAN 编号会变
- 确认同花顺走的是 WiFi（不是代理/VPN）
- dumpcap 需要管理员权限（右键 WiresharkPortable64.exe → 以管理员运行）

**Q: 抓到的数据是乱码？**
- 同花顺用 GBK 编码 + 自定义帧格式，不是 HTTP，Wireshark 无法直接解析
- 用 `follow tcp stream` 看原始字节，或导出后用项目脚本解析

**Q: 现在非盘中，能抓什么？**
- 8901 登录/行情：随时可抓
- 9601 历史翻页（qurealorder）：随时可抓（查的是历史数据）
- 9601 实时推送（pushrealorder）：**必须盘中**，非交易时段服务器不推
