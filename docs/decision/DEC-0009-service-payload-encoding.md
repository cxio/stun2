# 0009 — 三个服务原语的请求/响应 Payload 编码

## 背景

`DEC-0001` §「单次请求内的最小服务行为」定义了 `STUN:Addr`/`STUN:Cone`/`STUN:Live` 三个原语各自的语义，但未给出具体的二进制字段布局。本决策在 `DEC-0007`（帧格式）、`DEC-0008`（地址编码）、`DEC-0006`（Exclist 上限）的基础上，补齐三个原语的 Payload 编码。

`proposal/wire-spec-v1.md` §4 已经给出一套具体编码，本决策对其中确定无疑的部分予以收编；其中 `CONE_ACK` 原设计的 `Flags`/`ProbeWindowMs` 字段是否保留，经确认无需引入，结论见下方「`CONE_ACK` 保持空 Payload」一节。

## 决策

### 1. `STUN:Addr`

- `ADDR_REQ` Payload：空（`PayloadLen = 0`）。
- `ADDR_RESP` Payload：

  | 字段 | 长度 | 说明 |
  |------|------|------|
  | `Observed` | 18（`WireAddr`） | 服务端观察到的客户端地址 |

  服务端 **MUST** 从接收到该请求的底层 UDP 四元组（源地址）读取观测地址。

### 2. `STUN:Cone`

- `CONE_REQ` Payload：

  | 字段 | 长度 | 说明 |
  |------|------|------|
  | `Key32` | 32 | 会话密钥，**MUST** 为密码学随机 |
  | `ExclistCount` | 2（`uint16`） | **MUST** ≤ 256（`DEC-0006`） |
  | `Exclist` | `ExclistCount × 16` | 每项 16 字节，含义同 `LocalIP`（不含 `Port`） |

- `CONE_ACK` Payload：空（`PayloadLen = 0`，**MUST**）——服务端已接受请求，客户端收到后即按 `DEC-0003` 关闭 QUIC 连接、转入裸 UDP 探测等待。**不** 引入 `Flags`（`NewPortScheduled`/`NewHostScheduled`）或 `ProbeWindowMs` 等扩展字段（曾在 `proposal/wire-spec-v1.md` 早期草案中出现），理由见下方「`CONE_ACK` 保持空 Payload」。
- 若服务端因受托节点不足等原因无法安排探测，**MUST** 回复 `CONE_ERR`（`UNAVAILABLE_DELEGATE`），而非发送一个"部分接受"的 `CONE_ACK`（呼应 `conelevel.md`"如果服务端无法提供探测服务……会返回状态告知"，本决策将其固定为二选一的整体成败语义，不引入部分调度状态）。
- `CONE_ERR`：使用 `DEC-0007` 错误结构；常见 `UNAVAILABLE_DELEGATE`、`EXCLIST_TOO_LARGE`、`RATE_LIMITED`。

### 3. `STUN:Live`

- `LIVE_REQ` Payload：

  | 字段 | 长度 | 说明 |
  |------|------|------|
  | `Key32` | 32 | 本轮 transaction 会话密钥；**MUST** 每次请求新生成 |
  | `Port0` | 2（`uint16`） | 旧 `UDPConn` 映射端口（`STUN:Addr` 阶段获得） |

- `LIVE_ACK` Payload：空（`PayloadLen = 0`）。
- 服务端 **MUST** 从当前 QUIC 连接的客户端源 IP 与 `Port0` 构造探测目标地址（`clientIP:Port0`），该客户端源 IP 的取值语义与 `DEC-0004` 中服务端 `LocalIP` 的确定性要求对称：都必须取自本次连接的实际观测值，而非缓存/配置值。
- `LIVE_ERR`：使用 `DEC-0007` 错误结构；常见 `RATE_LIMITED`、`MALFORMED_REQUEST`。

### 4. `STUN:Live` 重复请求去重

服务端 **MUST** 将重复到达、且满足以下条件的 `LIVE_REQ` 视为同一 transaction（而非另起一轮独立的探测发送循环）：`ClientIP`、`Port0`、`Key32` 三者均相同，且前一个同键 transaction 尚未完成清理。此时服务端 **MAY** 重发 `LIVE_ACK`，但 **MUST NOT** 因此重启一轮新的探测 SN 发送。此规则用于防止客户端异常重发请求导致探测流量或服务端状态重复分配。

### 5. `CONE_ACK` 保持空 Payload（不引入 `Flags`/`ProbeWindowMs`）

`proposal/wire-spec-v1.md` 早期草案中 `CONE_ACK` 曾包含：

- `Flags`（1 字节：`NewPortScheduled`/`NewHostScheduled` 两个 bit）
- `ProbeWindowMs`（4 字节，服务端建议的客户端等待窗口）

经确认，**不** 引入这两个字段，`CONE_ACK` **MUST** 保持空 Payload（`PayloadLen = 0`），理由：

1. `conelevel.md` 原文对"服务无法提供"只描述了一种整体拒绝的结果（对应 `CONE_ERR`），未提及"部分路径可用、部分不可用"的中间状态，`Flags` 字段对应的场景在 Conception 中没有直接依据，属于未被验证需求的额外复杂度。
2. `DEC-0003` 已经把客户端的等待窗口定为纯粹的应用层/客户端本地配置项（默认 5 秒，`MAY` 自行调整），不需要服务端下发建议值；引入 `ProbeWindowMs` 只会制造一个客户端可以不理会的冗余字段。

若未来出现真实的委托延迟或部分调度场景，应先修订 Conception/新增 Decision 明确该场景的语义，再考虑扩展 `CONE_ACK` 的 Payload，而不是提前预留字段。

## 理由

- 三个原语的字段编码都是 `DEC-0001` 点名的协议层必须内容，两个独立实现在此不一致就无法互操作。
- `CONE_ACK` 采用"空 Payload、二选一整体成败"的极简设计，与 `conelevel.md` 原文描述的行为完全对应，且遵循"简单性优先"的整体设计取向；额外的部分调度语义（`Flags`/`ProbeWindowMs`）在没有明确应用需求前不引入，避免过度设计。
- Live 请求去重规则防止了因网络重传或客户端异常重复请求造成的资源/流量重复消耗，是协议正确性的必要保障，而非单纯的实现优化建议。

## 影响范围

- **Proposal**：`wire-spec-v1.md` §4 的 `ADDR_RESP`/`CONE_REQ`/`CONE_ACK`/`LIVE_REQ`/`LIVE_ACK` 字段表由本决策正式背书，`CONE_ACK` 为空 Payload 已定稿，不再是待决问题。`transaction-spec-v1.md` 中 `LiveTxKey` 概念与本决策的去重规则一致，可保留其作为服务端内部实现的组成键。
