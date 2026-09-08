# Web API 服务（单用户 REST，FastAPI）

> 前端（JS 架构）消费的后端接口层。单用户：进程内持有一个
> `THSClient`。`ThsRuntime` 只串行化首次登录；业务请求由库内
> MAIN/SH_L2/SZ_L2 等连接各自的 single-flight 锁保护，不同连接可并行。
>
> 个股实时推送已接入 `/api/stock-stream/{code}`：逐笔、十档、买卖一队列和
> 撤单共用后台唯一 `THSClient` 与市场 L2 socket，不产生额外登录。
> 短线精灵实时流已接入 `/api/dxjl/stream`（订阅后零遗漏，连接即回快照）。

## 启动

```powershell
uv sync --extra server
uv run --extra server python -m thspypc.server --host 127.0.0.1 --port 8765
```

账号从仓库根目录 `.env` 读取（`THS_USERNAME` / `THS_PASSWORD` / `THS_IMEI`），
也可用同名环境变量覆盖。启动后打开 <http://127.0.0.1:8765/docs> 查看自动生成的
OpenAPI 文档。

## 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 连接状态 / 账号类型 / 凭据是否就绪 |
| POST | `/api/connect` | 显式登录（MAIN） |
| GET | `/api/quote?codes=600519,000938` | 个股列表行情（自动按市场分组） |
| GET | `/api/depth/{code}?levels=5\|10` | 五档/十档盘口（10 档仅 L2 账号） |
| GET | `/api/kline/{code}?period=day&count=2146&anchor=0` | K线（1分/5/15/30/60分/日/周/月/季/年；anchor 翻页） |
| GET | `/api/timeline/{code}` | 当日分时 |
| GET | `/api/history_timeline/{code}?date=YYYY-MM-DD` | 历史分时 |
| GET | `/api/auction/{code}?trade_date=` | 早盘集合竞价 |
| GET | `/api/closing_auction/{code}?trade_date=` | 尾盘集合竞价 |
| GET | `/api/intraday/{code}?trade_date=` | 完整日内序列 |
| GET | `/api/stock-ready/{code}?market=` | 个股 4214 订阅注册（面板与 WS 扇出前先调一次） |
| GET | `/api/market_view/{code}?period=day&count=320&fuquan=Q&levels=5` | 单股页面聚合数据（行情 + 完整日内 + K 线 + 盘口） |
| GET | `/api/market_view_fast/{code}?levels=5` | 首屏行情与盘口（不包含分时） |
| GET | `/api/intraday/{code}` | 统一返回早盘竞价、盘中分时、尾盘竞价 |
| GET | `/api/intraday_auctions/{code}` | 兼容接口；新前端不再使用 |
| GET | `/api/superorder/{code}?start=&end=&pageid=4214\|4260&timeout=` | 7169 精确逐笔成交回放（timeout 3~25s 可缩短读预算；北交所代码自动切 7176 竞价窗路径，安静窗口需快速失败） |
| GET | `/api/superorder-bse/{code}?market=&timeout=` | 北交所当日超级盘口：1207 页 4096 全日逐笔（每行含五档快照），timeout 3~20s；仅当日，不缓存 |
| GET | `/api/order-details/{code}?start=&end=` | 7175 挂单 + 7170/7171 买卖撤单 |
| GET | `/api/order-queues/{code}?trade_date=` | 7173/7174 买一和卖一委托队列 |
| GET | `/api/superorder-replay/{code}?trade_date=` | 4096 回放轻量时间/价格/量索引（完整记录服务端缓存） |
| GET | `/api/superorder-replay/{code}/snapshot?ts=&trade_date=` | 缓存中离 ts 最近的完整十档快照 |
| GET | `/api/superorder-window/{code}?start=&end=` | 串行聚合7169与7175/7170/7171，窗口上限300秒 |
| WS | `/api/stock-stream/{code}?market=` | `trade/depth/order_queue/cancel/status` 统一个股事件流 |
| WS | `/api/dxjl/stream` | 短线精灵 9601 实时流：订阅后零遗漏推送；连接建立即回缓冲快照（空缓冲也回，前端据此解除加载态） |
| GET | `/api/stocks` | 全市场代码表（~7400 条，首次较慢） |
| GET | `/api/hot?count=29&sort_by=199112&sort_dir=D` | 排序榜单 |
| GET | `/api/stock_list_ranked?sort_by=199112&count=5400&sort_dir=D&with_values=1` | 全市场排序榜（L2 SortCount 放大一次拉全 ~0.1s；`sort_dir=A` 升序已实测） |
| GET | `/api/quotes_ext?codes=600519,000001` | 批量统一列表字段：涨幅/竞价涨幅/竞价金额/成交额/涨速（本地派生）+ 主力净额/ DDE 主力/总市值（0xc4 金额表 dt250/dt248/dt202，元/亿/元） |
| GET | `/api/dde_rank?sort_by=592888&count=58` | DDE 主力资金排行（value 单位亿，响应字段 248） |
| GET | `/api/stocks2` | 全市场代码表（带磁盘缓存，自然日有效，含 code/name/market） |
| GET | `/api/market_snapshot` | 全市场快照 |
| GET | `/api/boards?category=industry` | 系统板块列表（本地 oracle） |
| GET | `/api/board_categories` | 板块分类树（行业/概念/地域/同花顺一二级） |
| GET | `/api/hot_boards` | 热点板块全量行情（pageid=12480，513 个板块含涨跌家数/主力） |
| GET | `/api/board/{code}/constituents` | 板块成分股 |
| GET | `/api/board/{code}/quotes` | 板块行情 |
| GET | `/api/board/{code}/timeline?date=` | 板块指数分时 |
| GET | `/api/board/{code}/auction?date=` | 板块集合竞价 |
| GET | `/api/groups` | 自定义板块/分组列表 |
| GET | `/api/groups/{name}?refresh=false` | 单个自定义板块成分股 |
| GET | `/api/self_stocks` | 自选股（默认自选股分组） |
| GET | `/api/dynamic_plates` | 动态板块列表 `[{name, question, items}]`（云端快照；question 为问财语句） |
| GET | `/api/dynamic_plate_refresh?name=动态板块名` | 按问财语句实时重查成分股（非云端快照；404=板块不存在/无语句） |
| GET | `/api/dxjl?pages=5` | 短线精灵历史（无推送） |
| GET | `/api/dxjl/latest` | 短线精灵最新一页（前端轮询用） |

## 错误约定

- `400`：参数错误 / 不支持的功能（如普通账号请求十档之前的能力门禁）
- `403`：账号权限不足（如普通账号请求 L2 专属数据）
- `502`：后端连接/协议失败（登录失败、超时、通道不可用），`detail` 带原因

数据以 JSON 返回；`datetime` 字段自动序列化为 ISO 字符串。板块/分组等
dataclass 实体自动转成字典。

所有 HTTP 响应包含 `Server-Timing`，用于区分后端总耗时和连接排队，例如：

```text
total;dur=48.2, sh_l2_wait;dur=11.1, sh_l2_io;dur=31.9, app;dur=43.4
```

- `main_wait` / `sh_l2_wait` / `sz_l2_wait`：等待对应连接 single-flight 锁。
- `main_io` / `sh_l2_io` / `sz_l2_io`：持有连接、发送并读取协议响应的时间。
- `lifecycle_wait`：仅冷启动登录时可能出现的生命周期锁等待。
- `app`：业务方法总时间；`total` 还包含 FastAPI 序列化等 HTTP 层时间。

## 设计说明

- 单用户：`ThsRuntime` 懒创建唯一 `THSClient`，首次业务调用自动登录；
  首次登录持生命周期锁，业务调用不持跨连接全局锁。
- 服务启动后后台预热 MAIN、SH_L2、SZ_L2；Uvicorn 不等待预热完成即可监听，
  `/api/status` 的 `preheat.state` 和 `preheat.markets` 可查看进度与结果。
  每条新 L2 socket 在登录前独立刷新 Passport64，已建立的 MAIN 不会被关闭；
  普通或账号类型仍未知时跳过 L2 预热。
- 若以后要多人/多账号，把 `ThsRuntime` 改成"每账号一个实例"的池即可，
  REST 契约不变。
- WebSocket 按股票引用计数并扇出；4214注册、后台reader和7169/4096/717x查询
  共用同一市场连接锁。查询期间先到的主动推送交回统一事件分发器，不双读、不丢帧。
- 4096 完整记录只保存在最多8项的进程内LRU缓存；浏览器先取轻量索引，点选光标
  后再取一条完整十档。当前日缓存60秒，历史日缓存1小时。
- 北交所超级盘口（`/api/superorder-bse`）走 `BSE_MAIN` 连接（仅 main.123ths.com
  组），当日全日 ~1000 行不缓存；前端失败后回退竞价窗（`/api/superorder`
  的 7176 窗口）与 `/api/intraday` 的 6144 竞价点。
- 服务退出时 `ThsRuntime.close()` 会关闭唯一客户端和全部socket，降低热重启后的
  服务端旧会话残留概率。

## 相关文件

- `src/thspypc/server/runtime.py`：`ThsRuntime`（唯一 client + 登录生命周期锁）
- `src/thspypc/server/app.py`：`create_app()`（FastAPI 路由 + 错误映射）
- `src/thspypc/server/__main__.py`：`python -m thspypc.server`
- `tests/test_server_api.py`：路由/错误映射离线契约（`uv run --extra server pytest`）
