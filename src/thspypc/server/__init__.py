"""单用户 Web API 服务：把 THSClient 包成 REST 接口（FastAPI）。

设计约定：
- 单用户：进程内持有一个 :class:`thspypc.client.THSClient`，所有请求经
  :class:`ThsRuntime` 的全局锁串行化（复用库内 single-flight，避免并发抢
  一条 8901 socket）。
- 只做请求-响应（REST）；实时推送（短线精灵/快照订阅）待盘中抓包核对后再
  加 WebSocket。
- 前端不接触协议细节：本层负责把 dt 字段/异常翻译成业务 JSON。
"""

from .app import create_app
from .runtime import ThsRuntime

__all__ = ["create_app", "ThsRuntime"]
