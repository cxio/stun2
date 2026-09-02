## QUIC + 裸 UDP 机制

核心技术依赖 quic-go 的「同一 UDPConn 复用 QUIC + 裸 UDP」机制成立，已经在之前的评审中确认。


## quic-go 的四个行为假设

经对 fork `github.com/cxio/quic-wtls`（上游 v0.61.0）逐项核验，SPEC-0004 的四项假设均成立：

1. `Transport.StatelessResetKey == nil` ⇒ **不发送** Stateless Reset（`transport.go:631` 前置拦截；nil 的 resetter 只用于给对端生成 token，不发包）。无 server 的 client 侧 Transport 上，未匹配长/短头包亦静默丢弃。
2. 关闭残留窗口精确为 `3*PTO`。窗口内重传为收包触发的指数退避（第 1、2、4、8... 个到达包），Live 场景通常零重传。
3. `Conn.ConnectionStats()` 存在且全字段导出，`CloseWithError` 前任意时刻可调；v0.53+ 最低版本满足。
4. `Transport.ReadNonQUICPacket` 在零活跃 Conn 时依然可读；非 QUIC 判定在 conn ID 查找之前（首字节高两位 0）。单一逻辑读取点（首次调用前的到达包会被丢弃，要避免漏包须提前发起一次调用）。
