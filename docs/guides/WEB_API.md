# Web API 服务（单用户 REST，FastAPI）

> 前端（JS 架构）消费的后端接口层。单用户：进程内持有一个
> `THSClient`，所有请求经 `ThsRuntime` 全局锁串行化（复用库内
> single-flight，避免并发抢一条 8901 socket）。
>
> 实时推送（短线精灵 / 快照订阅）暂未接入——待盘中抓包核对后再加
> WebSocket 通道。

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
| GET | `/api/stocks` | 全市场代码表（~7400 条，首次较慢） |
| GET | `/api/hot?count=29&sort_by=199112&sort_dir=D` | 排序榜单 |
| GET | `/api/market_snapshot` | 全市场快照 |
| GET | `/api/boards?category=industry` | 系统板块列表（本地 oracle） |
| GET | `/api/board/{code}/constituents` | 板块成分股 |
| GET | `/api/board/{code}/quotes` | 板块行情 |
| GET | `/api/board/{code}/timeline?date=` | 板块指数分时 |
| GET | `/api/board/{code}/auction?date=` | 板块集合竞价 |
| GET | `/api/groups` | 自定义板块/分组列表 |
| GET | `/api/dxjl?pages=5` | 短线精灵历史（无推送） |

## 错误约定

- `400`：参数错误 / 不支持的功能（如普通账号请求十档之前的能力门禁）
- `403`：账号权限不足（如普通账号请求 L2 专属数据）
- `502`：后端连接/协议失败（登录失败、超时、通道不可用），`detail` 带原因

数据以 JSON 返回；`datetime` 字段自动序列化为 ISO 字符串。板块/分组等
dataclass 实体自动转成字典。

## 设计说明

- 单用户：`ThsRuntime` 懒创建唯一 `THSClient`，首次业务调用自动登录；
  所有调用持同一把 RLock（`runtime.call`）。
- 若以后要多人/多账号，把 `ThsRuntime` 改成"每账号一个实例"的池即可，
  REST 契约不变。
- 实时推送接口（`subscribe_realtime` / `snapshot_subscribe`）等盘中抓包
  核对字段后，以 WebSocket 通道加入。

## 相关文件

- `src/thspypc/server/runtime.py`：`ThsRuntime`（唯一 client + 全局锁）
- `src/thspypc/server/app.py`：`create_app()`（FastAPI 路由 + 错误映射）
- `src/thspypc/server/__main__.py`：`python -m thspypc.server`
- `tests/test_server_api.py`：路由/错误映射离线契约（`uv run --extra server pytest`）
