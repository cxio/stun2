# 0007 — 控制面帧格式与 QUIC 传输模型

## 背景

`DEC-0001` §「Wire Format」明确把"请求/响应消息的编码方案"、"`msg_type`/`version`/`request_id` 字段"、"错误/状态码集合"列为协议层 **必须** 定义的内容（两个独立实现若在此不一致，将无法互相解析消息）。此前 `proposal/wire-spec-v1.md` 已经给出一套具体的帧格式（`Magic`/`Version`/`MsgType`/`RequestID`/`PayloadLen` 九字节帧头、`MsgType` 枚举、错误码结构与具体码值），但这些数值从未有对应的 `DEC-NNNN` 文档背书，违反了本项目"Proposal 不得默认选值固化"的治理规则（见 `docs/AGENTS.md`）。本决策把这批已经在实践中验证过、并无异议的数值正式收编为 Decision。

`proposal/wire-spec-v1.md` 待决问题 **W1**（"是否在 v2 引入 `request_id` 级别的 QUIC datagram 模式"）：本决策 **不处理**，v1 固定使用 QUIC stream 承载控制消息，datagram 模式留待未来视需要另行评估，不在当前决策范围内。

## 决策

### 1. 字节序

所有多字节整数字段 **MUST** 采用大端（network byte order）编码。

### 2. QUIC 控制流传输模型

每个控制 transaction **MUST** 使用一条独立的 QUIC **双向 stream**：

1. 客户端打开一条新 stream；
2. 客户端在该 stream 上写入 **一条** 完整的控制消息（请求）；
3. 服务端读取该请求，在同一 stream 上写入 **一条** 完整的响应；
4. 双方关闭该 stream（**MUST NOT** 因此关闭底层 `UDPConn`）。

单条控制消息 **MUST** 在单个 stream 上完整表达（允许底层一次 `Write` 调用分段发送，但对端 **MUST** 按下述帧格式重组为完整消息，不依赖额外的分片语义）。v1 **不** 使用 QUIC datagram 承载控制消息（对应 W1，留待日后决定）。

### 3. 控制帧头（9 字节，所有控制消息共有）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | `Magic` | 固定 `0x53`（ASCII `'S'`，STUN2 控制帧标识） |
| 1 | 1 | `Version` | 协议版本；v1 固定 `0x01`（对应此前 L-1 决议：单字节宽度） |
| 2 | 1 | `MsgType` | 消息类型，见下表 |
| 3 | 4 | `RequestID` | 客户端生成的 `uint32`；请求与对应响应 **MUST** 相同 |
| 7 | 2 | `PayloadLen` | 后续 Payload 字节数（`uint16`）；**MUST** ≤ `4130` （CONE_REQ: 32+2+256×16=4130） |

帧头之后紧跟 `PayloadLen` 字节的 Payload。读取方在 `PayloadLen` 超过 4130、或剩余数据不足 `PayloadLen` 声明的长度时，**MUST** 判定为 `MALFORMED_REQUEST`。

### 4. `MsgType` 枚举

| 值 | 名称 | 方向 | 说明 |
|----|------|------|------|
| `0x01` | `ADDR_REQ` | C→S | 请求公网映射地址 |
| `0x02` | `ADDR_RESP` | S→C | 返回观察地址 |
| `0x03` | `ADDR_ERR` | S→C | 地址请求失败 |
| `0x10` | `CONE_REQ` | C→S | 发起 NAT 类型探测 |
| `0x11` | `CONE_ACK` | S→C | 接受探测请求（触发客户端关闭 QUIC，进入裸 UDP 探测阶段） |
| `0x12` | `CONE_ERR` | S→C | 拒绝或无法服务 |
| `0x20` | `LIVE_REQ` | C→S | 发起单次存活期探测 |
| `0x21` | `LIVE_ACK` | S→C | 接受，即将向 `Port0` 发 SN |
| `0x22` | `LIVE_ERR` | S→C | 拒绝或无法服务 |

### 5. 错误 Payload 结构与状态码

所有 `*_ERR` 响应的 Payload **MUST** 以如下结构开头：

| 字段 | 长度 | 说明 |
|------|------|------|
| `Status` | 2（`uint16`） | 状态码，见下表 |
| `ReasonLen` | 2（`uint16`） | 后续 `Reason` 字节数；**MAY** 为 0 |
| `Reason` | `ReasonLen` | UTF-8 诊断文本（可选）；**MUST NOT** 参与协议逻辑判断 |

| Status | 名称 | 说明 |
|--------|------|------|
| `0x0001` | `UNSUPPORTED_VERSION` | `Version` 字段不被支持 |
| `0x0002` | `MALFORMED_REQUEST` | 帧或字段解析失败 |
| `0x0003` | `UNAVAILABLE_DELEGATE` | 无法安排 `NewHost` 受托（`CONE` 专用） |
| `0x0004` | `RATE_LIMITED` | 限流 |
| `0x0005` | `EXCLIST_TOO_LARGE` | `Exclist` 超出上限（`DEC-0006`，`CONE` 专用） |

### 6. 常量

| 常量 | 值 |
|------|-----|
| `Magic` | `0x53` |
| `Version` | `0x01` |
| `MaxPayloadLen` | `4130` |

## 理由

- 帧格式、`MsgType`、错误码集合属于 `DEC-0001` 已经明确划归协议层的内容，两个独立实现若各自发明不同编码就无法互通，必须统一。
- `Magic` 字节的作用与 SN 首字节"高 2 位清零"同源：都是为了让接收方能快速区分控制帧、探测 SN 与真实 QUIC 包，避免定向丢弃或误解析。
- 每个 transaction 独立一条 QUIC stream、单条消息一次性收发，是当前最简单可靠的模型，暂不引入 datagram 模式（无丢包重传保障、需要额外处理乱序/丢失），留待有明确性能诉求时再评估（即 W1）。

## 影响范围

- **Proposal**：`wire-spec-v1.md` §1.1–§1.3、§2.1–§2.3、§8（`Magic`/`Version`/`MaxPayloadLen` 部分）中已有数值由本决策正式背书，无需修改；`MsgType` 中 `CONE_ACK` 的具体 Payload 内容见 `DEC-0009`。
- **待决**：W1（v2 datagram 模式）明确保留为未来待决问题，不在本决策处理范围。
