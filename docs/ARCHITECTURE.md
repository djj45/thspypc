# thspypc 架构与演进约束

本文描述当前代码的稳定边界，以及后续增加协议功能时应遵守的迁移顺序。目标是
渐进式拆分，不进行一次性重写，也不破坏已有公开导入路径。

## 当前分层

```text
THSClient                         公开门面、登录与功能编排
    ├── MarketSession             8901 同步请求生命周期
    ├── BlockManager              自定义板块/自选股 HTTP 能力
    ├── 4214 manual connections   沪深 L2 分时与竞价
    └── 9601 realorder            异动历史与实时推送

protocol.py                       请求构造、响应解析、数值/压缩编解码
parse_hfd1.py                     全市场快照解码
qr_login.py                       二维码和凭证缓存
```

`THSClient` 和 `protocol.py` 仍然偏大。后续按“修改到哪个功能，就迁移哪个功能”
逐步拆分，旧模块保留兼容性 re-export。

## 连接不变量

8901 响应可能被 `CodeListSize`、`MarketTime`、心跳等帧穿插，且当前没有可直接
关联公开请求的 request id。因此：

1. 每条 8901 socket 同一时间只能有一个同步业务请求；
2. 请求锁必须覆盖设置 timeout、发送、读取和匹配全部响应；
3. 业务请求进行中，后台心跳跳过本轮发送；
4. 不允许功能方法脱离 `MarketSession` 新增“只锁 send、锁外 read”的代码；
5. 需要真正并行时，应增加独立连接或实现单 reader + 帧分发器，不能让多个线程
   直接读取同一 socket。

当前 `MarketSession` 是同步 single-flight 实现。它是安全基线，不代表未来不能
升级为 dispatcher。

## 新功能的纵向切片

每个新功能按以下路径交付：

1. 保存并标注最小请求/响应样本；
2. 在协议层实现纯函数 builder/parser；
3. 为 builder/parser 增加离线回归；
4. 通过正确的 session/channel 接入 `THSClient`；
5. 明确无数据、超时、权限不足和不支持帧的语义；
6. 完成多市场、多股票、多交易日活网验证；
7. 更新 `FEATURE_GAP_ROADMAP.md`。

五档盘口 `depth_quote` 是第一条按此路径接入的门面功能。

## 计划中的模块边界

只有在对应功能发生修改时才迁移，避免纯搬家式大改：

```text
transport/    8901、4214、9601 的连接、重试和帧读取
codecs/       hd1/hd3、压缩、位流和数值编码
features/     quote、kline、timeline、auction、depth、stock_list
services/     system_blocks、fund_flow、f10、watchlists
models.py     稳定业务字段及原始 dt 字段的兼容容器
errors.py     超时、权限、协议、无数据等错误分类
```

F10、系统板块等 HTTP 能力应作为独立 service，不进入 8901 `MarketSession`。

## 测试边界

计划逐步整理为：

```text
tests/unit/          无网络、每次必跑
tests/fixtures/      脱敏后的协议真值与元数据
tests/integration/   需要账号/网络，默认不跑
tools/capture/       抓包工具
tools/reverse/       一次性逆向和诊断脚本
```

在目录迁移完成前，新代码至少要有无需账号的离线测试，活网脚本不能作为唯一验收。
