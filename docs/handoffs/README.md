# 交接文档索引

> [返回文档总目录](../README.md)

本目录集中保存阶段性开发、重构和协议逆向交接记录。文档中未特别说明的代码、
测试和抓包路径均相对仓库根目录。

| 文档 | 内容 |
|------|------|
| [`HANDOFF.md`](HANDOFF.md) | 项目综合交接；包含 2026-07-29 Level2 历史尾盘修复结论 |
| [`HANDOFF_REFACTOR_20260728.md`](HANDOFF_REFACTOR_20260728.md) | `client.py` / `protocol.py` 渐进重构 |
| [`HANDOFF_HISTORY_TIMELINE_20260728.md`](HANDOFF_HISTORY_TIMELINE_20260728.md) | 历史分时专项 |
| [`HANDOFF_STOCKLIST_PUSH.md`](HANDOFF_STOCKLIST_PUSH.md) | 股票列表与推送采集 |
| [`HANDOFF_HFD1_0_20260809.md`](HANDOFF_HFD1_0_20260809.md) | hfd1.0 全市场快照专项：统一入口 + 语料 + 攻破路线 |
| [`HANDOFF_PUSH_INVESTIGATION_20260724.md`](HANDOFF_PUSH_INVESTIGATION_20260724.md) | 个股分时推送调查 |
| [`HANDOFF_SUPERORDER_20260726.md`](HANDOFF_SUPERORDER_20260726.md) | 集合竞价与超级盘口 |
| [`HANDOFF_SYSTEM_BLOCKS_CAPTURE_20260801.md`](HANDOFF_SYSTEM_BLOCKS_CAPTURE_20260801.md) | 系统板块 P0：抓包驱动逆向（block_hq 缓存 oracle） |
| [`HANDOFF_WEB_DASHBOARD.md`](HANDOFF_WEB_DASHBOARD.md) | Web 看板与字段逆向 |

这些文件包含历史调查过程；结论发生变化时，以文档顶部的纠正说明、较新章节以及
生产代码和回归测试为准。
