# 公网地址获取：`STUN:Addr`

客户端连接服务器，首先需要请求对端告知自己的NAT公网映射地址（`IP:Port`），此即最基础的 `STUN:Addr` 服务。


## 地址格式

连接可能通过 `IPv6` 链路，也可能是 `IPv4` 链路，因此返回的 IP 地址统一为 `IPv6` 格式，即 IPv4 地址使用 `IPv4-mapped IPv6` 编码（`::ffff:IPv4`）。
