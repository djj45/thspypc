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
   `thspypc.testing.get_client()`；已有 8901 socket 时直接复用该 socket，
   不要新建客户端或额外 socket 再登录一次。

3. 只有明确测试单 IP/单服务器时才能显式指定一个 host，并且要在脚本里注明原因。

4. 一个 HTTP 鉴权生成的通行证（Passport64）允许在首次登录阶段并发竞速多个
   8901 候选服务器，这也是当前代码和同花顺客户端的行为；但一旦任意服务器返回
   `VerifyCode=0`，该通行证就视为已被此次成功登录消费。此后必须复用获胜的
   socket，不能再拿同一通行证新登录另一个 8901 host，否则服务端会返回
   `VerifyCode=-1`，并提示“登录通行证有被修改的痕迹”。首次成功后若确实需要
   登录另一个服务器或新建另一条 8901 socket，必须先重新执行 HTTP 鉴权，取得
   新的通行证。
