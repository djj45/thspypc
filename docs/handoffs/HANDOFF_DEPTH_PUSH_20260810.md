# 十档盘口实时推送收口交接（2026-08-10）

## 明日目标

把已有 549B 十档盘口推送底层能力收口成生产可用 API，并在交易时段完成沪深
Level2 活网验证。不是重新破译十档字段。

## 已有基础

- `features/snapshot_protocol.py` 已实现 `is_depth_push()` / `parse_depth_push()`；
- 549B `09 7b d0 0f` 帧可解析完整买卖十档、最新价、昨收、开高低；
- `ConnectionRuntime.snapshot_loop()` 已识别 549B 并写入 `latest_depth`；
- `client.snapshot_subscribe()` 可建立 4214 订阅；
- `client.latest_depth(code)` 可轮询读取最后一帧。

## 仍需实现

1. 增加专用十档事件消费方式，避免复用当前只接收
   `callback(code, market, price, volume)` 的逐 tick 回调。可选接口：
   `depth_callback(record)` 或 `subscribe_depth()` / `receive_depth_pushes()`。
2. 明确多代码、多市场订阅和退订行为；关闭页面后停止无用订阅，但复用已成功登录
   的 SH_L2/SZ_L2 socket，不能每只股票重新鉴权或登录。
3. 处理读线程所有权、断线、重复帧、慢回调和停止流程。
4. 普通账号必须在打开 L2 socket 前返回能力错误。
5. 补服务/生命周期离线测试和两市 10 档字段回归。

## 交易时段验收

- 沪市、深市各选至少一只活跃股票，连续接收多帧 549B；
- 每帧 `bids` / `asks` 各 10 档，价格顺序和数量合理；
- 与同时刻 `depth_quote(ten_levels=True)` 或客户端盘口交叉验证；
- 换股后旧代码退订、新代码开始更新，多代码模式互不串码；
- 停止订阅后读线程和 socket 生命周期符合预期；
- 普通账号权限门控通过。

登录诊断遵守仓库 `AGENTS.md`：一个 Passport64 首次成功后只能复用获胜 socket；
若需另一市场新连接，必须取得新鲜 HTTP 鉴权材料，不能用已消费票据登录另一节点。

## 与 DDE 的关系

DDE 前端未来也可以消费这套实时盘口事件，但本任务不实现 `DDESession`。当前
`dde_rank()` 已满足后端排名数据 API；DDE 可见窗口 AddCode/DelCode、分页缓存和
实时行字段合并等到正式开发前端时再做。
