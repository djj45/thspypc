# tests/archive/ — 已完成使命的一次性诊断脚本

这些脚本在项目早期用于定位特定问题，结论已沉淀到主代码或文档。
保留供回溯参考，但不再是常规测试流程的一部分。

## 脚本说明

### diag_no_heartbeat.py（原 test_no_heartbeat.py）
**问题**：不发心跳时，8901 连接多久会被服务器断开？
**结论**：心跳是必要的。逐档二分（30/60/90/120/150/180/240/300s）确认
不发自心跳时连接很快失效，因此 `client.py` 默认每 3s 发心跳（8901）/30s（9601）。
**现状**：结论已体现在 `test_heartbeat.py`（验证保活有效）和 src 默认开启心跳的行为。

### compare_remember.py + remember_*.json（未保留于此）
**问题**：「30天免登录」勾选/不勾选的差异？
**结论**：唯一差异是服务端返回的 `expireTime` 字段——
不勾选 = `"0"`，勾选 = 未来时间戳（如 `"1786805623"` ≈ 30天后）。
其他字段（account/password/imei）完全一致。
**注意**：原 JSON 含明文设备凭据（account/password/imei/qrid），已从工作区删除，
未归档到此目录。如需复现，用 `tests/compare_remember.py` 重新跑一次即可。
