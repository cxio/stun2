# 0001 — 协议层与应用层的边界划分

## 判定标准

- **协议层**：两个独立实现如果不一致，就无法互通、无法解析、无法验证，或对同一消息得出不同语义。
- **应用层**：不同实现选择不同策略也不影响协议消息的解析和验证，仅影响成功率、成本、可靠性。

> STUN2 协议层定义 **一次请求/回应长什么样、怎么算合法、对端收到后应立刻做什么**。
> 应用层定义 **什么时候请求、请求谁、失败后怎么换节点、跑几轮、结果怎么用**。

---

## 协议层（STUN2 必须定义）

### 1. 传输绑定

- QUIC 安全控制通道 + 同一 `net.UDPConn` 上的裸 UDP 探测包
- `quic.Transport{Conn: udpConn}` + `Transport.ReadNonQUICPacket()` 模式
- SN 首字节高两位清零，避免被识别为 QUIC packet
- QUIC 承载控制消息和密钥，裸 UDP 只承载探测 SN

### 2. 三个服务原语

| 原语 | 语义 |
|------|------|
| `STUN:Addr` | 服务端即时返回观察到的客户端公网地址 |
| `STUN:Cone` | 服务端即时发起 NewPort / NewHost 探测包 |
| `STUN:Live` | 服务端即时向旧 NAT 映射端口发探测包，等待并验证客户端回应 |

### 3. Wire Format

- 请求/响应消息的编码方案
- `msg_type`、`version`、`request_id` 字段（如采用）
- 错误/状态码集合：`OK`、`UNAVAILABLE_DELEGATE`、`RATE_LIMITED`、`MALFORMED_REQUEST`、`UNSUPPORTED_VERSION` 等
- 各字段的二进制布局：`IP`、`Port`、`Key32`、`SN`、`Exclist`、`Port.0`

### 4. SN 构造与验证

- `Rnd16`（16 字节）、`TmpN`（464–1024 字节）
- `Rnd16[0]` 位规则：高 2 位清零防 QUIC 误判
- `HMAC_SHA256` 算法、HMAC 输入的字节拼接顺序（无长度前缀，无对齐）
- **Cone**：`Rnd16[0] = Rnd16[0] & 0x3E | from`；NewPort 用 `Key32`，NewHost 用 `SHA256(Key32)`
- **Keepalive**：`Rnd16[0] &= 0x3F`；`SN = Rnd16 + HMAC(Key32, Rnd16 + LocalIP + TmpN) + TmpN`
- `LocalIP` 定长 16 字节（IPv4 走 IPv4-mapped IPv6，即 `::ffff:a.b.c.d`）
- 验证失败 → 丢弃，不作为有效探测包

### 5. 单次请求内的最小服务行为

**STUN:Addr**：服务端立即返回观察到的客户端 IPv4:Port 或 IPv6:Port。

**STUN:Cone**：
- 请求字段：`Key32`、`Exclist`
- 服务端接受后应触发 `NewPort`（同机新端口发 SN）和 `NewHost`（同机新 IP 或受托服务器发 SN）
- 双路并发执行
- 不设计客户端回应 Cone 探测包
- 客户端从 SN 的 `Rnd16[0].bit0` 识别 `NewPort`（0）或 `NewHost`（1）

**STUN:Live**：
- 请求字段：`Key32`、`Port.0`
- 服务端从新 QUIC 连接提取客户端 IP，构造目标 `clientIP:Port.0`
- 服务端立即向旧映射地址发送 SN 并按退避策略冗余发送（收到有效回应后停止）
- 客户端收到后验证，并用同一 `Key32` 重新构造 SN 回应
- 服务端收到有效回应即停止本轮发送

### 6. NAT 类型结果语义

枚举：`Open Internet`、`UDP Firewall`、`Full Cone`、`Restricted Cone`、`Port Restricted Cone`、`Symmetric Like`、`UDP Blocked`

Cone 判断矩阵：

| NewPort 收到 | NewHost 收到 | 与本地地址相同 | 结果 |
|:---:|:---:|:---:|------|
| - | Y | N | Full Cone |
| Y | N | N | Restricted Cone |
| N | N | N | Port Restricted Cone |
| - | Y | Y | Open Internet |
| - | N | Y | UDP Firewall |

---

## 应用层（不属于 STUN2 协议）

### 1. 服务节点发现与选择

- 接入 P2P 网络、获取 SPKI/ECH/UDP 地址
- 过滤毒 IP、健康检查、节点缓存、优先级排序
- → 属于 `cxio/p2p` 或上层应用

### 2. UDP Blocked 判定策略

协议层只定义 UDP Blocked 这个结果名，以下归应用层：
- 尝试几个节点、单次超时多久、失败几次判定
- 是否先通过 TCP 获取 UDP 地址

### 3. STUN:Addr 多节点预探测策略

- 请求几个服务器、最少成功数（3 可配置）
- 部分不一致时如何判定、重试间隔、置信度统计
- 协议层最多提供纯函数辅助（`AddrsEqual()`），策略由应用控制

### 4. Exclist 维护策略

字段格式归协议层，以下归应用层：
- "近期"是半小时还是十分钟
- 如何裁剪、是否持久化、是否按 IP/网段去重

### 5. NewHost 受托节点选择

协议层定义 NewHost 的 SN 密钥规则。以下归应用层：
- 本机第二 IP 还是委托其他节点
- 委托谁、如何发现可用节点、失败是否重试
- 限流策略

### 6. PoW / Equi-X / 反滥用

默认归应用层 / 服务网络层（`stun2p`）。PoW 不影响客户端验证 SN。
例外：如需标准化受托 Notice 消息格式以便不同 `stun2p` 实现互通，可将 Notice 基础字段格式放入协议层，PoW 参数仍放应用层。

**补充**：「Notice 基础字段格式已由 DEC-0005 正式纳入协议层」。

### 7. Keepalive 探测节奏

协议层只定义单次 `STUN:Live` transaction。以下归应用层：
- 等 15s / 30s / 60s
- 粗测倍增策略、精测二分逼近
- 精度设置（5s / 1s）、最大探测时长
- 是否跨服务器做粗测/精测

### 8. 超时、重试、置信度

- 客户端等 Cone 5 秒、等 Live 12 秒 → 协议可给推荐值，不强制
- 是否提前结束、是否重试、是否多轮取多数 → 应用层

---

## 边界易混淆项速查

| 项目 | 归类 | 说明 |
|------|------|------|
| `STUN:Addr` 请求/响应格式 | 协议层 | 互操作必需 |
| 请求多少个 `STUN:Addr` 服务器 | 应用层 | 策略问题 |
| `STUN:Cone` 请求字段 | 协议层 | 互操作必需 |
| `Exclist` 字段格式 | 协议层 | 出现在请求中 |
| `Exclist` 如何维护 | 应用层 | 客户端策略 |
| `NewHost` 的 SN 密钥规则 | 协议层 | 验证必需 |
| 选择哪个受托服务器 | 应用层 | 服务网络策略 |
| `STUN:Live` 单次交互 | 协议层 | 互操作必需 |
| Live 粗测/精测算法 | 应用层 | 客户端调度策略 |
| NAT 类型枚举 | 协议层 | 结果统一命名 |
| 结果置信度、多轮验证 | 应用层 | 策略问题 |
| QUIC stream 承载方式 | 协议层 | 互操作必需 |
| 连接池、重试、节点缓存 | 应用层 | 工程实现 |

---

## 后续 Proposal 结构建议

1. **`proposal/wire-spec-v1.md`**（强规范）
   消息格式、字段表、SN 二进制布局、状态码、单次 transaction 行为

2. **`proposal/client-algorithm-notes.md`**（参考）
   多节点预探测、Cone 重试策略、Live 粗测/精测调度

3. **`proposal/server-operation-notes.md`**（参考）
   受托节点选择、限流、PoW、状态返回建议

只有第 1 份是强规范；第 2、3 份是实现建议，不影响协议互通。
