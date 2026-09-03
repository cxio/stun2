# DEC-0002 控制面 RPC 形态

## 背景 （Context）

三篇构想都在已建立的 QUIC 上发请求，`pubaddr.md` 与 `keepalive.md` 已钉死 Stream 模式。没有统一信封时，Addr / Cone.* / Live.* / 服务器间委托会各写一套编解码，Version 与失败形态也无法共用。通路失败已改为直接关 QUIC，不再需要结束请求。

## 决策 （Decision）

1. **信封。** 控制面统一为「方法名 + Version + 载荷」。`STUN:Addr`、`STUN:Cone.Passage`、`STUN:Cone.Inquire`、`STUN:Cone`、`STUN:Cone.Challenge`、`STUN:Cone.NewHost`、`STUN:Live.Port`、`STUN:Live` 共用同一信封。方法名沿用构想中的协议域标签，不另起别名。
2. **Stream 用法。** 每个请求在 QUIC 连接上新开一条双向 Stream，响应走同一条 Stream，结束后关闭该 Stream。不在一条长流上排队多个请求（避免通路确认 4s/6s 被队头阻塞）。不使用 DATAGRAM。
3. **版本。** 未知或不支持的 Version 一律拒绝，不降级、不静默忽略。
4. **失败。** 拒绝必须可区分原因，至少覆盖：未知方法、不支持的 Version、校验失败（含 Equi-X / Validation / Challenge）、受托不足或收集不够下限、限速。数值错误码与字节布局留给 Spec。
5. **通路失败。** 客户端判定 `QUIC Only` 后只关 QUIC 连接，不发额外控制请求（构想已写明）。

## 理由 （Rationale）

方法名已在构想里作为协议标签存在，信封只需把它们变成可分派的控制面，而不是再发明一套 RPC。每请求一流与 Stream 模式兼容，且通路探测的超时是硬编码短窗口，长流排队会把确认和后续 Inquire 绑在一起。失败可区分，是为了客户端把「受托不足」和「Version 不对」分开处理，而不是都当成超时。

## 影响 （Consequences）

- Spec 只设计一种控制信封；服务器间 Challenge / NewHost 与客户端请求同一套。
- 实现必须能并发打开多条 Stream（例如 NewPort 与 NewHost 委托同时进行时，控制面仍可能有独立请求）。
- 通路失败没有 Abort 报文，服务端在发出确认后仍会按构想发完 2 个裸 UDP 包；客户端已关闭则丢弃即可。

## 构想层依据 （Conception References）

- `conception/pubaddr.md`：QUIC Stream；Version 不符返回错误。
- `conception/conelevel.md`：各请求带 Version；通路失败关 QUIC；Inquire 收集不够下限返回错误。
- `conception/keepalive.md`：Stream 模式；`STUN:Live.Port` / `STUN:Live` 带 Version。

## 开放问题 （Open Questions）

无。
