# SN Spec v1 — 探测面会话标识（Session Nonce）二进制布局与验证

## 来源追溯

| 来源 | 章节 |
|------|------|
| `conception/conelevel.md` | 会话标识、受托服务器、客户端（Step.3） |
| `conception/keepalive.md` | 会话标识、附：SN 验证、服务端操作 |
| `decision/DEC-0001-layer-boundary.md` | SN 构造与验证 |
| `decision/DEC-0002-transaction-concurrency.md` | 并发约束对 SN demux 的影响 |
| `decision/DEC-0004-live-localip-binding.md` | Keepalive `LocalIP` 取值来源与绑定建议 |

本文档为 **强规范**，覆盖 **探测面**（裸 UDP，非 QUIC packet）承载的 SN 字节格式与验证规则。控制面帧格式见 `wire-spec-v1.md`；SN 在 transaction 中的时序与状态机见 `transaction-spec-v1.md`。

SN **MUST NOT** 出现在 QUIC stream 中，仅通过 `Transport.ReadNonQUICPacket()`（或等价接口）读取。

---

## 1. 总体布局

```
+----------------+----------------------------+------------------+
| Rnd16 (16)     | HMAC_SHA256 (32)           | TmpN (464..1024) |
+----------------+----------------------------+------------------+
```

| 字段 | 长度 | 说明 |
|------|------|------|
| `Rnd16` | 16 | 密码学随机；首字节位规则见 §2 |
| `HMAC` | 32 | HMAC-SHA256 输出 |
| `TmpN` | 464–1024 | 密码学随机；长度 **MUST** 在范围内均匀随机选取，用于隐藏 SN 的长度特征 |

总长度：**512–1072** 字节。每次发送 **MUST** 重新生成完整 SN（含新 `Rnd16`、新 `TmpN`、新 HMAC），避免链路中间件的优化合并或丢弃。

---

## 2. `Rnd16[0]` 位规则（Cone 与 Keepalive 不同，不可互相套用）

两套协议中 `Rnd16[0]` 的高 2 位（bit7、bit6）**MUST** 恒为 `0`（避免与 QUIC 首字节混淆、被误判为 QUIC packet）。除此之外两者规则不同：

### 2.1 Cone（`STUN:Cone`）

```
bit7 bit6 bit5 bit4 bit3 bit2 bit1 bit0
  0    0   ←—————随机—————→        from
```

- bit0 = `from`：`0` = `NewPort`，`1` = `NewHost`。
- bit5–bit1 **SHOULD** 保持随机。
- 构造：`Rnd16[0] = Rnd16[0] & 0x3E | from`。

### 2.2 Keepalive（`STUN:Live`）

```
bit7 bit6 bit5 bit4 bit3 bit2 bit1 bit0
  0    0   ←———————随机———————→
```

- **无** `from` 语义，bit5–bit0 **SHOULD** 保持随机。
- 构造：`Rnd16[0] &= 0x3F`。

客户端 **MUST** 依据当前 transaction 类型（Cone 或 Live）选用对应的位解析规则，二者不可互相套用。

---

## 3. HMAC 输入构造（无长度前缀，直接拼接）

### 3.1 Cone — NewPort

```
input = Rnd16 || TmpN
key   = Key32
```

### 3.2 Cone — NewHost（含源服务器从本机新 IP 发送的情形）

```
input = Rnd16 || TmpN
key   = SHA256(Key32)    // 32 字节摘要作为 HMAC key，而非原始 Key32
```

密钥封装的目的是防止受托服务器伪装客户端；源服务器从自己本机新 IP 发送 `NewHost` 时（未委托其他节点）**同样 MUST** 使用封装后的密钥，因为客户端借助 `from` 位判断应使用的密钥值，与是否真实发生了跨服务器委托无关。

### 3.3 Keepalive — 服务端发出的 SN

```
input = Rnd16 || LocalIP || TmpN
key   = Key32
LocalIP = 服务端 IP，16 字节 IPv4-mapped IPv6 编码
```

### 3.4 Keepalive — 客户端回应的 SN

```
input = Rnd16 || LocalIP || TmpN
key   = Key32
LocalIP = 客户端公网 IP（与 STUN:Addr 观察地址的 IP 部分一致），16 字节
```

验证失败 **MUST** 丢弃该 UDP 包，不视为有效探测（见 §6）。

---

## 4. `LocalIP` 取值规则（`DEC-0004`）

- **协议层 MUST**：服务端构造 Keepalive SN 时使用的 `LocalIP` **MUST** 等于客户端本次实际拨号连接所使用的那个具体服务 IP（该 QUIC 连接的服务端地址），**而非** 任何配置层面声明的"规范"服务器身份地址。
- **实现建议 SHOULD**：服务端 **SHOULD** 按每一个对外提供服务的公网 IP 分别绑定独立的 `net.UDPConn`（及对应 `quic.Transport` 实例），而非绑定通配地址，以确保发送 SN 时能准确控制所使用的源 IP；多个服务 IP（IPv4/IPv6 双栈、多出口）应相应绑定多个 socket。
- 客户端一侧的 `LocalIP` **MUST** 为其公网映射 IP（与同一次会话中 `STUN:Addr` 观察地址的 IP 部分一致），16 字节编码规则与 `wire-spec-v1.md` §3 的 `WireAddr` 共用同一套 IPv4-mapped IPv6 表示。

`Rnd16 || TmpN` 之间不含 `LocalIP` 是 Cone 协议特有设计（`conelevel.md`"会话标识"节：SN 构造中没有服务端地址，因为对客户端来说受托服务器未知，无法验证），不要与 Keepalive 的 `LocalIP` 规则混淆。

---

## 5. SN 与 `Key32` 的绑定规则

- **Cone**：同一 `CONE_REQ` 内的所有 `NewPort`/`NewHost` SN **MUST** 使用该请求中的同一 `Key32`（`NewHost` 侧 HMAC key 仍为 `SHA256(Key32)`，见 §3.2）。
- **Live**：SN **MUST** 使用对应 `LIVE_REQ` 中的 `Key32`；不同 transaction 的 `Key32` **MUST** 不同（客户端责任，用于服务端去重与状态隔离，见 `wire-spec-v1.md` §4.3）。
- **禁止按远端 IP 区分 transaction**（`DEC-0002`）：`NewHost` 子路径源 IP 对客户端设计上不可预知，任何实现 **MUST NOT** 依赖远端 IP 作为 SN 归属判定手段；同一 `net.UDPConn` 上任意时刻最多只有一个处于探测等待状态的 Cone/Live transaction（详见 `transaction-spec-v1.md` §1）。

---

## 6. 验证失败处理

- 长度不在 512–1072 字节范围内的 UDP 载荷 **MUST NOT** 被当作 SN 处理。
- `Rnd16[0] & 0xC0 != 0` 的载荷 **MUST** 直接丢弃。
- HMAC 校验不通过的载荷 **MUST** 丢弃，不视为有效探测；**MUST NOT** 触发任何协议层重试或错误上报（探测面无回应机制，Cone 侧本身不设计客户端回应；Live 侧仅在客户端一侧首次收到有效服务端 SN 后才回应，见 `transaction-spec-v1.md` §3）。
- 客户端/服务端 **MUST NOT** 对验证失败的探测面数据包做任何形式的重放缓存（无活跃 transaction 时收到的 SN **MUST** 丢弃；`transaction-spec-v1.md` §1.2）。

---

## 7. 常量

| 常量 | 值 |
|------|-----|
| `SNMinLen` | 512 |
| `SNMaxLen` | 1072 |
| `TmpNMin` | 464 |
| `TmpNMax` | 1024 |
| `Rnd16Len` | 16 |
| `HMACLen` | 32 |
| `LocalIPLen`（Keepalive HMAC 输入用） | 16 |

---

## 边界与限制

- 本文档不涉及控制面帧格式（见 `wire-spec-v1.md`），不涉及 SN 在 transaction 中的发送时机、冗余次数、超时窗口（见 `transaction-spec-v1.md`）。
- NewHost 受托节点的选择策略、委托对象发现 **不** 在本文档范围（应用层，`DEC-0001`）。
- PoW / Equi-X **不** 出现在客户端 SN 验证路径中（`conelevel.md`"附：源服务器安全"）。

---

## 待决问题

（无；SN 构造与验证规则已由 Conception + `DEC-0001`/`DEC-0002`/`DEC-0004` 完整覆盖。）

---

## 对 Plan 的约束

1. 包 `internal/sn`（或同等）**MUST** 实现 §1–§3 的 Cone/Live 两套 SN 构造与验证，测试向量须覆盖：NewPort/NewHost 密钥差异、`Rnd16[0]` 位规则区分、`LocalIP` 布局、边界长度（512/1072、464/1024）。
2. 验证失败路径（§6）**MUST** 有专门的单元测试，确认丢弃行为不产生任何副作用（无重试、无状态变更）。
3. `internal/sn` **MUST NOT** 依赖远端 IP 做 transaction 归属判定（对应 §5 `DEC-0002` 约束），实现时应通过"当前活跃 transaction 唯一"的方式满足此约束，而非按 Key 遍历。
