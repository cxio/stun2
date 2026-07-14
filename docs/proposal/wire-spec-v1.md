# Wire Spec v1 — STUN2 控制面二进制格式

## 来源追溯

| 来源 | 章节 |
|------|------|
| `conception/conelevel.md` | 公网NAT映射地址获取（`STUN:Addr`）、客户端 Step.1、受托服务器 |
| `conception/keepalive.md` | 客户端 Step.2、服务端操作 |
| `decision/DEC-0001-layer-boundary.md` | Wire Format、三个服务原语 |
| `decision/DEC-0005-newhost-notice-format.md` | Notice 消息字段格式 |
| `decision/DEC-0006-exclist-upper-bound.md` | `Exclist` 容量上限 |
| `decision/DEC-0007-control-frame-format.md` | 控制帧头、`MsgType`、错误码、字节序、QUIC 传输模型 |
| `decision/DEC-0008-wire-address-format.md` | `WireAddr` 地址编码 |
| `decision/DEC-0009-service-payload-encoding.md` | 三个原语的 Payload 编码、Live 去重规则 |

本文档为 **强规范**（MUST/SHOULD/MAY 语义见 RFC 2119 惯例），覆盖 **控制面**（QUIC stream 承载）的二进制格式。探测面 SN 的格式见 `sn-spec-v1.md`；状态机与时序见 `transaction-spec-v1.md`。与 Conception/Decision 冲突时以 Conception/Decision 为准；本文档细节以 Decision 为直接依据。

---

## 1. 传输模型

### 1.1 双平面

| 平面 | 承载 | 内容 | 规格文档 |
|------|------|------|---------|
| 控制面 | QUIC（`quic.Transport{Conn: udpConn}`） | `STUN:Addr` / `STUN:Cone` / `STUN:Live` 请求与响应 | 本文档 |
| 探测面 | 同一 `net.UDPConn` 上的裸 UDP | SN 字节序列（非 QUIC packet） | `sn-spec-v1.md` |

实现 **MUST** 使用外部传入的 `net.UDPConn`，通过 `Transport.ReadNonQUICPacket()` 读取探测面包，与 QUIC 包复用同一 socket（`DEC-0001` §1）。

### 1.2 QUIC 控制流模型（`DEC-0007` §2）

每个控制 transaction **MUST** 使用一条独立的 QUIC **双向 stream**：

1. 客户端 `OpenStreamSync()` 打开 stream；
2. 客户端写入 **一条** 完整控制消息（见 §2）；
3. 服务端读取请求，写入 **一条** 响应消息；
4. 双方关闭该 stream（**MUST NOT** 因此关闭底层 `UDPConn`）。

单条消息 **MUST** 在单个 stream 上一次性写入（一次 `Write` 调用可分段，但对端按 §2 帧格式重组）。v1 **不** 使用 QUIC datagram 承载控制消息；是否在未来版本引入见「待决问题」P-W1。

### 1.3 字节序（`DEC-0007` §1）

多字节整数均为 **大端（network byte order）**，除非另有说明。

---

## 2. 控制消息帧格式（`DEC-0007` §3–§5）

### 2.1 帧头（9 字节，所有控制消息共有）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Magic      |    Version    |   MsgType     |              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+              +
|                       RequestID (uint32)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          PayloadLen (uint16)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | `Magic` | 固定 `0x53`（ASCII `'S'`） |
| 1 | 1 | `Version` | 协议版本；v1 固定 `0x01` |
| 2 | 1 | `MsgType` | 消息类型，见 §2.2 |
| 3 | 4 | `RequestID` | 客户端生成的 uint32；请求与对应响应 **MUST** 相同 |
| 7 | 2 | `PayloadLen` | 后续 Payload 字节数；**MUST** ≤ 4130 |

帧头之后紧跟 `PayloadLen` 字节的 Payload。读取方 **MUST** 在 `PayloadLen` 超过 4130 或剩余数据不足时判定为 `MALFORMED_REQUEST`。

### 2.2 `MsgType` 枚举

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

### 2.3 错误 Payload 与状态码

所有 `*_ERR` 响应的 Payload **MUST** 以如下结构开头：

```
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Status (uint16)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     ReasonLen (uint16)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Reason (UTF-8, 可选)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Status | 名称 | 说明 |
|--------|------|------|
| `0x0001` | `UNSUPPORTED_VERSION` | `Version` 字段不被支持 |
| `0x0002` | `MALFORMED_REQUEST` | 帧或字段解析失败 |
| `0x0003` | `UNAVAILABLE_DELEGATE` | 无法安排 `NewHost` 受托（`CONE` 专用） |
| `0x0004` | `RATE_LIMITED` | 限流 |
| `0x0005` | `EXCLIST_TOO_LARGE` | `Exclist` 超出上限（`DEC-0006`，`CONE` 专用） |

`ReasonLen` **MAY** 为 0；若非 0，`Reason` 为诊断用 UTF-8 文本，**MUST NOT** 参与协议逻辑判断。

---

## 3. 地址编码 `WireAddr`（18 字节，`DEC-0008`）

所有控制消息中的 `IP:Port` **MUST** 使用定长 `WireAddr`：

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        IP (16 bytes)                          |
|                       IPv6-mapped form                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Port (uint16)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**IPv4** **MUST** 编码为 IPv4-mapped IPv6：`::ffff:a.b.c.d`（前 10 字节 0，第 11–12 字节 `0xFF 0xFF`，后 4 字节为 IPv4）。**IPv6** 使用标准 16 字节地址。`Port` 为 UDP 端口号（uint16 BE）。

> 与 SN 中的 `LocalIP`（16 字节、无 `Port`）同族表示；见 `sn-spec-v1.md` §4。

---

## 4. 各服务 Payload（`DEC-0009`）

### 4.1 `STUN:Addr`

**`ADDR_REQ` Payload**：空（`PayloadLen = 0`）。

**`ADDR_RESP` Payload**：

| 字段 | 长度 | 说明 |
|------|------|------|
| `Observed` | 18（`WireAddr`） | 服务端观察到的客户端地址 |

服务端 **MUST** 从接收到该请求的底层 UDP 四元组（源地址）读取观察地址。

### 4.2 `STUN:Cone`

**`CONE_REQ` Payload**：

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Key32 (32 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    ExclistCount (uint16)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Exclist (ExclistCount × 16)  |  每项为 IPv6-mapped IP，无 Port
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 字段 | 约束 |
|------|------|
| `Key32` | 32 字节，**MUST** 为密码学随机 |
| `ExclistCount` | uint16；**MUST** ≤ `MaxExclistEntries`（**256**，`DEC-0006`，不可协商） |
| `Exclist` | 每项 16 字节，含义同 `LocalIP` |

**`CONE_ACK` Payload**：空（`PayloadLen = 0`）——服务端已接受请求；客户端收到后按 `transaction-spec-v1.md` §2 关闭 QUIC 连接、转入裸 UDP 探测等待。**不** 携带 `Flags`/`ProbeWindowMs` 等扩展字段，此为定稿结论，不再作为待决问题（`DEC-0009` §5）。

若服务端因受托节点不足等原因无法安排探测，**MUST** 回复 `CONE_ERR(UNAVAILABLE_DELEGATE)`，而非发送"部分接受"的 `CONE_ACK`——`CONE_ACK`/`CONE_ERR` 是整体成败的二选一语义，不存在中间调度状态（`DEC-0009`）。

**`CONE_ERR`**：§2.3 错误结构；常见 `UNAVAILABLE_DELEGATE`、`EXCLIST_TOO_LARGE`、`RATE_LIMITED`。

### 4.3 `STUN:Live`

**`LIVE_REQ` Payload**：

| 字段 | 长度 | 说明 |
|------|------|------|
| `Key32` | 32 | 本轮 transaction 会话密钥；**MUST** 每次请求新生成 |
| `Port0` | 2 | uint16 BE；旧 `UDPConn` 映射端口（`STUN:Addr` 阶段获得） |

**`LIVE_ACK` Payload**：空（`PayloadLen = 0`）。

服务端 **MUST** 从 **当前** QUIC 连接的客户端源 IP + `Port0` 构造探测目标 `WireAddr{IP=clientIP, Port=Port0}`；该客户端源 IP **MUST** 取自本次连接的实际观测值，不得使用缓存/配置值（`DEC-0009` §3，语义对称于 `DEC-0004` 的服务端 `LocalIP` 规则）。

**`LIVE_ERR`**：§2.3；常见 `RATE_LIMITED`、`MALFORMED_REQUEST`。

**去重规则**：服务端 **MUST** 将 `(ClientIP, Port0, Key32)` 三者均相同、且前一个同键 transaction 尚未完成清理的重复 `LIVE_REQ` 视为同一 transaction；**MAY** 重发 `LIVE_ACK`，但 **MUST NOT** 因此重启一轮新的探测 SN 发送循环（`DEC-0009` §4）。

---

## 5. 受托服务器 Notice 消息格式（`DEC-0005`）

`NewHost` 委托流程中，委托服务器向受托服务器发送 `Notice` 消息（QUIC 安全连接承载，**不** 出现在面向客户端的裸 UDP 探测面，格式与 §2 控制帧的收发关系由 `stun2p` 等上层服务间协作协议决定，本节仅规定字段布局）：

| 字段 | 长度 | 说明 |
|------|------|------|
| `Version` | 1 字节 | 版本号，初始值 `1` |
| `ClientAddr` | 18（`WireAddr`） | 客户端公网映射地址 |
| `KeyDigest` | 32 字节 | 客户端会话密钥封装 `SHA256(Key32)`（**不** 传递原始 `Key32`） |
| `AppIDLen` | 1 字节（`uint8`） | `0` 表示未提供 `AppID` |
| `AppID` | `AppIDLen` 字节，UTF-8 | 应用实现自身标识（可选），**MUST** ≤ 64 字节 |
| `AppDataLen` | 2 字节（`uint16` BE） | `0` 表示未提供 `AppData` |
| `AppData` | `AppDataLen` 字节，不透明 | 应用自身额外数据（可选），**MUST** ≤ 1024 字节 |

**行为规则**：

1. 受托服务器 **MUST** 将 `AppID`/`AppData` 视为不透明扩展数据；**MUST NOT** 仅因无法识别 `AppID` 或不理解 `AppData` 内容而拒绝该 `Notice`——只有固定字段（`Version`/`ClientAddr`/`KeyDigest`）解析失败时才可拒绝。
2. 委托方未使用 `AppID`/`AppData` 时，**MUST** 将对应长度字段填 `0`（而非省略字段），保持消息结构定长可解析。
3. 源服务器从自己本机新 IP 发送 `NewHost`（未委托给其他节点）时，**MUST** 同样对 SN 使用封装后的密钥 `SHA256(Key32)`（见 `sn-spec-v1.md` §3.2），但此时不涉及 `Notice` 消息本身（`Notice` 仅用于服务器间委托）。

---

## 6. 常量与上限（v1）

| 常量 | 值 | 来源 |
|------|-----|------|
| `Magic` | `0x53` | `DEC-0007` |
| `Version` | `0x01` | `DEC-0007` |
| `MaxPayloadLen` | 4130 | `DEC-0007` |
| `MaxExclistEntries` | 256 | `DEC-0006` |
| `MaxAppIDLen` | 64 | `DEC-0005` |
| `MaxAppDataLen` | 1024 | `DEC-0005` |

SN 相关常量（`SNMinLen`/`SNMaxLen`/`TmpNMin`/`TmpNMax`）见 `sn-spec-v1.md` §7。

---

## 边界与限制

- 本文档只定义 **控制面** 帧格式；探测面 SN 格式见 `sn-spec-v1.md`；状态机与时序见 `transaction-spec-v1.md`。
- 多节点 `STUN:Addr` 预探测策略、Cone 多轮重试、Live 粗测/精测调度、Exclist 维护策略 **不** 在本文档范围（应用层，`DEC-0001`）。
- PoW / Equi-X 参数 **不** 出现在本文档（`DEC-0001` §「PoW / Equi-X / 反滥用」，应用层/`stun2p`）。
- QUIC TLS / ECH / SPKI 由 `cxio/p2p` 提供，不在本文档范围。

---

## 待决问题

| ID | 问题 | 影响 | 状态 |
|----|------|------|------|
| P-W1 | 是否在 v2 引入 `RequestID` 级别的 QUIC datagram 模式 | 仅优化；v1 固定 stream | 待定（`DEC-0007` 明确搁置） |

`CONE_ACK` 是否携带 `Flags`/`ProbeWindowMs` 已经确认无需引入（`DEC-0009` §5），空 Payload 为定稿结论，不再列为待决项。

---

## 对 Plan 的约束

1. 包 `internal/wire`（或同等）**MUST** 实现 §2 帧编解码、§3 `WireAddr`、§4 各原语 Payload 编解码、§5 `Notice` 编解码，并提供 round-trip 测试。
2. 公开 API 不得暴露未在 Conception/Decision 定义的应用层策略；控制消息类型与字段以本文档为准。
