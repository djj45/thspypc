# 盘口推送真实帧夹具

这些 `.hex` 文件由
`captures_live/kanpan_push_20260810_091444.pcap` 的服务端 8901 帧裁出，保存的是
去掉 TCP/THS framing 后交给 `parse_depth_push()` 的完整 body。

| 文件 | 抓包相对时间 | 真值 |
|---|---:|---|
| `auction_sell_002428.hex` | 59.003576s | 109.00，撮合 353400，卖方未匹配 47428 |
| `auction_buy_002428.hex` | 296.012242s | 107.89，撮合 437428，买方未匹配 172 |
| `continuous_000657.hex` | 898.762650s | 550B 标准十档，现价 69.05 |
| `variable_c51_two_records.hex` | 10.215964s | 770B 变长帧，native 还原为 600000/600012 两条 707B 记录 |
| `variable_c57_three_records.hex` | 23.756018s | 855B 变长帧，native 还原为 300308/300322/300394 三条 707B 记录 |

文本十六进制格式便于代码审查；测试用 `bytes.fromhex()` 恢复原始 body。
