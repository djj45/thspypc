# DDE 排名页

`THSClient.dde_rank()` 实现了 Windows 客户端 DDE 页的 `pageid=10723`
排名请求。普通账号走 MAIN 单路由 `0x0148`；Level2 账号分别走沪市、深市
连接的 `0x0149` 路由，再按响应中的真实数值合并为全市场顺序。

```python
rows = client.dde_rank(
    count=58,
    sort_by=592888,
    sort_dir="D",
    with_names=True,
)
```

每条记录包含：

- `code`、`name`、`market`；
- `value`：服务器返回的排序值；
- `sort_by`：请求使用的完整排序键；
- `response_field`：紧凑响应中的字段号。

当前抓包已验证的键如下：

| `sort_by` | 响应字段 | 页面含义 |
| ---: | ---: | --- |
| 592888 | 248 | DDE 默认列（主力净量） |
| 592890 | 250 | 主力净流入 |
| 199112 | 200 | 涨幅 |
| 19 | 19 | 成交额 |
| 48 | 48 | 涨速 |
| 1968584 | 200 | 换手率 |

`dt200` 被涨幅和换手率复用，因此调用方应依据 `sort_by`，不能只根据
`response_field` 判断语义。592889 对应 `dt249` 的映射已经保留，但列名仍待
进一步确认。

Level2 `0x0149` 路由中的 592888 线值使用 `1e8` 放大单位，而普通 MAIN
`0x0148` 返回直接显示值；服务层会统一归一化，所以两类账号的 `value` 可以直接
比较。响应还会按请求序号严格关联，避免误收新建 L2 连接中残留的初始化排名帧。

DDE 页右侧个股组件不需要新协议：分时、盘口和日 K 分别复用
`client.timeline()`、`client.depth_quote()` 和 `client.kline()`。列表下拉加载通过
增大 `count` 完成；普通账号内部使用 `SortBegin` 分页，Level2 账号分别扩大沪深
前缀并重新执行全市场合并。表头排序传对应的 `sort_by` 和 `sort_dir="A"/"D"`。
