# 文档目录

本项目文档按两类划分：**长期有效的参考资料**（手册、架构、规划）与**阶段性记录**（专项调查、交接流水）。文中未特别说明的路径均相对仓库根目录。

## 一、手册与指南（长期有效）`docs/guides/`

| 文档 | 内容 | 何时阅读 |
|------|------|---------|
| [`THS_REVERSE_ENGINEERING_PLAYBOOK.md`](guides/THS_REVERSE_ENGINEERING_PLAYBOOK.md) | 同花顺协议逆向方法论与实战复盘：分层判定、语料设计、镜像重建、Unicorn oracle、回归验收 | 做任何逆向前先读 |
| [`PROTOCOL_AND_IMPLEMENTATION_GUIDE.md`](guides/PROTOCOL_AND_IMPLEMENTATION_GUIDE.md) | 行情协议与 thspypc 实现指南：登录、请求构造、响应解析、系统板块、代码地图 | 理解项目实现时首选 |
| [`CAPTURE.md`](guides/CAPTURE.md) | 同花顺 PC 抓包操作手册：工具位置、网卡选择、脚本 | 需要抓包时查阅 |
| [`DDE.md`](guides/DDE.md) | DDE 排名页协议与 `dde_rank()` 交付边界 | 做 DDE 前端或排名查询时查阅 |
| [`ORDER_QUEUE.md`](guides/ORDER_QUEUE.md) | Level2 买一/卖一委托队列 7173/7174 语义与 API | 做委托队列相关功能时查阅 |
| [`WEB_API.md`](guides/WEB_API.md) | FastAPI 单用户 REST 服务启动、接口与错误约定 | 使用/扩展 Web API 时查阅 |
| [`x32dbg_变体A调试手册.md`](guides/x32dbg_变体A调试手册.md) | x32dbg 动态调试操作手册（name_16_16 块状编码、断点、dump） | 需要动态调试 hexin.exe 时查阅 |

## 二、架构解析（长期有效）`docs/architecture/`

| 文档 | 内容 |
|------|------|
| [`ARCHITECTURE.md`](architecture/ARCHITECTURE.md) | 代码分层、连接不变量、协议功能演进约束 |
| [`SERVER_MATRIX.md`](architecture/SERVER_MATRIX.md) | 行情服务器域名、权限、路由矩阵（8901/9601） |

## 三、规划与路线图 `docs/plans/`

| 文档 | 内容 |
|------|------|
| [`FEATURE_GAP_ROADMAP.md`](plans/FEATURE_GAP_ROADMAP.md) | 同花顺 PC 功能缺口对照表与实现优先级依据，随进度更新 |
| [`SH_AUCTION_X86_HARNESS_PLAN.md`](plans/SH_AUCTION_X86_HARNESS_PLAN.md) | 沪市竞价 32 位离线 harness 实施计划 |

## 四、专项调查与复盘记录（阶段性）`docs/investigations/`

历史分时省略型 codec 系列按时间顺序阅读，结论发生矛盾时**以最新一篇为准**：

| 文档 | 内容 |
|------|------|
| [`HISTORY_TIMELINE_VARLEN_INVESTIGATION.md`](investigations/HISTORY_TIMELINE_VARLEN_INVESTIGATION.md) | 历史分时变长帧调查：三层结构、抓包语料 |
| [`HISTORY_TIMELINE_OMISSION_CODEC_HANDOFF.md`](investigations/HISTORY_TIMELINE_OMISSION_CODEC_HANDOFF.md) | 省略型 codec 攻坚计划 |
| [`HISTORY_TIMELINE_OMISSION_STEP1_FINDINGS.md`](investigations/HISTORY_TIMELINE_OMISSION_STEP1_FINDINGS.md) | 第 1 步：DP 结构对齐（定宽 92B 说法已降级） |
| [`HISTORY_TIMELINE_OMISSION_STEP2_RE.md`](investigations/HISTORY_TIMELINE_OMISSION_STEP2_RE.md) | 第 2 步：官方客户端逆向定位（核心结论已撤回） |
| [`HISTORY_TIMELINE_OMISSION_CORRECTION_HANDOFF.md`](investigations/HISTORY_TIMELINE_OMISSION_CORRECTION_HANDOFF.md) | 分支错位更正：撤回 STEP2 的 esi==1 结论 |
| [`HISTORY_TIMELINE_OMISSION_INVESTIGATION_UPDATE.md`](investigations/HISTORY_TIMELINE_OMISSION_INVESTIGATION_UPDATE.md) | Unicorn 执行校验与变长结构更正（当前最新结论） |
| [`NAME_16_16_MEMORY_DUMP_PROGRESS.md`](investigations/NAME_16_16_MEMORY_DUMP_PROGRESS.md) | 股票名称 `name_16_16` 内存/网络全量同步逆向 |
| [`POSTMORTEM_CONSTITUENT_20260801.md`](investigations/POSTMORTEM_CONSTITUENT_20260801.md) | 成分股空列表故障复盘：直接机制、根因与五条长期有效的排查教训 |

## 五、交接记录（会话流水）`docs/handoffs/`

[`handoffs/README.md`](handoffs/README.md) 是按日期整理的开发、重构与协议逆向交接索引；这类文档保留完整调查过程，结论变化时以文档顶部的更正说明、较新章节以及生产代码/回归测试为准。

## 阅读建议

- 新接触项目：先读 `PROTOCOL_AND_IMPLEMENTATION_GUIDE.md` → `ARCHITECTURE.md` → `SERVER_MATRIX.md`；
- 准备逆向：先读 `THS_REVERSE_ENGINEERING_PLAYBOOK.md`，再按需查阅对应专项调查；
- 只查结论：优先看手册/架构/规划，调查与交接记录作为证据链背景。
