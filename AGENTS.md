# AGENTS.md

## 测试/诊断脚本登录规则

1. 不要手写串行登录：
   ```python
   for ip in ips:
       sock.connect((ip, 8901))
   ```
   这会在一批不可达 IP 上逐个等 3 秒，最后整体超时。低层裸 socket 登录统一用
   `thspypc.testing.login_socket_for_domains()` / `login_socket()`。

2. 不要重复登录：
   同一个进程里先检查/复用已有 `THSClient`，用
   `thspypc.testing.get_client()`；需要额外低层 socket 时从同一个
   `AuthService` 取 passport，不要新建客户端再 `connect()` 一次。

3. 只有明确测试单 IP/单服务器时才能显式指定一个 host，并且要在脚本里注明原因。
