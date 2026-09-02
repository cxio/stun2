# SPEC-0004 `STUN:Live`

## 来源追溯

- `conception/keepalive.md` 全文。
- `DEC-0001`：状态机 + Runner；一次调用一个地址族；库按流程建连与关连；不持久化粗测进度。
- `DEC-0002`：`STUN:Live.Port` / `STUN:Live` 共用信封。
- `DEC-0004`：旧路径保留 Transport，只读裸 UDP；抑制 Stateless Reset；首次 `Time.0` 在关闭残留之后。
- `DEC-0005`：服务端短暂表闭集中与本服务相关的两项——Key32 发送窗、按被测 Address 的 10s 限速。
- SPEC-0001：信封、SN、Validation HMAC、常量。
- SPEC-0002：地址观测语义；本服务用 `STUN:Live.Port` 而非 `STUN:Addr` 取批条。


## 概述

规定存活期探测的载荷、静默路径、服务端短暂表，以及粗测 / 精测状态机。控制通道不必与被测映射同公网 IP。控制连接断开则丢弃本轮，不把上次成功间隔记为存活期。


## 规格正文

### 1. 方法载荷

**`STUN:Live.Port` 请求：**

```
Distance     u16 大端     秒；初始窗口 + 余量。0 为 InvalidPayload
```

**响应：**

```
ClientAddr   18 字节
Validation   u16+字节     见 SPEC-0001 §7
```

服务端用当前 QUIC 对端作 `ClientAddr`，`distanceSec = min(请求 Distance, 2700)` 签发 Validation。

**`STUN:Live` 请求：**

```
Key32        32 字节      每次当场生成
Address      18 字节      被测映射（预探测暂存的 ClientAddr）
Distance     u16 大端     至下次请求前的时长 + 余量（秒）
Validation   u16+字节
```

**响应：**

```
Validation   u16+字节     按 Address 与 min(Distance, 2700) 重签
```

然后从 **Listener 同一 IP:Port** 按发送表向 Address 发 SN（`domainTag=Server@STUN:Live`，`Key=Key32`）。

### 2. 客户端流程

#### 2.1 预探测

`DialUDP`（或等价已连接 Socket）建 QUIC，发 `STUN:Live.Port`。`ClientAddr` 与本机源地址 `Equal` → 结束，结果为「无需测存活期」（Open Internet | UDP Firewall），不进入正式探测。本机源地址须为实际网卡通讯 IP，禁止通配地址（同 SPEC-0002 注意）。否则暂存 `ClientAddr` 与 `Validation`。

#### 2.2 Step.1 静默旧路径（硬不变量）

1. 对旧 `quic.Conn` 调用 `CloseWithError`（必须发出 `CONNECTION_CLOSE`），不得只 `Transport.Close()` / 本地 destroy。
2. **保留**旧 `quic.Transport`，不再对该 Transport `Dial` / `Listen` / `AddPath`。
3. 构造该 Transport 时 **`StatelessResetKey` 必须为 nil**（quic-go：未配置则不发 Stateless Reset）。库创建的探测 Transport 一律不设此字段。应用注入的 Transport 若已设置 key，不得用于 `STUN:Live` 旧路径（Runner 应拒绝或要求调用方提供未设 key 的 Transport）。
4. `quic.Config.DisablePathMTUDiscovery = true`，避免额外 UDP。
5. 等待关闭残留结束（见 §2.3），**然后**记录首次 `Time.0`。
6. 此后旧路径只调用 `ReadNonQUICPacket()`（应用注入 Transport 时经 `PushNonQUICPacket` 投递，见 SPEC-0003 §5）。从 `Time.0` 到本轮结束，对该四元组抓包：除服务端 SN 与客户端对 SN 的回应外，不应出现其它 UDP 载荷。

新控制通道：新随机端口向同一节点拨号，正常 keep-alive。换网或控制连接断开：丢弃本轮，不产出存活期；若继续，从 §2.1 重新开始。

#### 2.3 关闭残留等待

quic-go 对已关闭连接的 `CONNECTION_CLOSE` 重传窗口为 `3*PTO`。等待方式：

1. 在 `CloseWithError` **之前**读取 `conn.ConnectionStats()`（quic-go v0.53+）。
2. `pto = SmoothedRTT + 4*MeanDeviation`；若 `SmoothedRTT == 0` 或 `pto < 1ms`，则 `pto = 1s`。
3. `CloseWithError` 之后等待 `3*pto`（可被 `ctx` 取消）。
4. 若所选 quic-go 无 `ConnectionStats`，等待固定 `3s`。Plan 在 `go get` 后核对符号；不得静默跳过等待。

后续每一轮的 `Time.0` 为对 SN 的**最后一次**客户端回包时刻，不再加关闭残留。

例外：若某版本在无连接、key 为 nil 的 Transport 上仍自发 UDP，则记录为被迫 `UDPConn.ReadFrom` 的例外路径，但仍须先关 Conn、等残留、再停 Transport，并满足 §2.2 抓包验收。默认路径不拆栈。

#### 2.4 Step.2 请求与收包

到达探测间隔后，在新 QUIC 上发 `STUN:Live`。客户端自**发出该 `STUN:Live` 请求**起 **10s**（硬编码）内若无有效服务端 SN，判定映射已失效。不以收到新 Validation 为起点：服务端发完 Validation 即发 SN，裸 UDP 的 SN 可能先期抵达（构想「状态判断」注记）。

收到服务端 SN（`VerifySN`，tag=`Server@STUN:Live`，Key=本轮 Key32）后立即回一个客户端 SN（tag=`Client@STUN:Live`，同一 Key32，新 Rnd16/TmpN）。最多回 8 次（与服务端发送上限一致）。每次有效回包更新 `Time.0`。

`探测间隔` = 本次 `Time.0` 到发出下一次 `STUN:Live` 的时长。

### 3. 粗测与精测

间隔单位与比较用 `time.Duration`。起始间隔 `Start` **必填**，`< 10s` 为配置错误。精测精度 `Precision` 可配，默认 5s（指两轮间隔之差，不是存活期本身）。

**粗测：**

记 `lastSuccess`、`lastFail`、`step`。第一次探测间隔为 `Start`。

- 成功：`lastSuccess = current`；`step = current`；`next = 2*current`。
- 失败：`next = current - step/2`；`step = step/2`。首次即失败时视 `step = Start`，故 `next = Start/2`。
- 若 `next` 将超过 45 分钟：改为测 **40 分钟**。40 分钟成功则结果为 40 分钟（上限，实际可能更长）；失败则按失败规则回退。
- **结束（正常）：** 出现「失败 → 成功」后，结果为最后一次成功间隔。
- **结束（迭代上限）：** 可配置次数上限（默认不限制或由调用方设）。到达上限仍无「失败→成功」则取 `lastSuccess`；若从未成功，返回 error（配置过高或异常，换节点由应用决定）。
- 每一次**失败**后的再测必须从 §2.1 重建映射。成功后的下一间隔仍在同一轮（同一旧映射、同一控制通道）上继续 Step.2。

**精测**（可与粗测不同服务器；必须从 §2.1 起新的一轮）：

输入粗测的 `n = lastSuccess`、`M = lastFail`（无 `lastFail` 则不能精测）。`D = M-n`。`step = D/2`，`current = n + step`。

```
循环：
  测试 current
  若成功：lastSuccess = current
  若 step < Precision：结束
  step = step / 2
  成功则 current += step，失败则 current -= step
```

与构想示例一致：会执行那次 `step < Precision` 的测试，再停。结果为精测过程中最后一次成功；若精测从未成功，结果为 `n`。失败后同样回 §2.1。

粗测因一直成功触达上限、没有 `M` 时，不能进入精测；Runner 返回粗测上限结果并标明未收敛。

### 4. 服务端

#### 4.1 Validation 与限速

验 Validation（SPEC-0001 §7）：过期或 HMAC 不符 → `VerifyFailed`。Address 必须与证明绑定的 IP:Port 一致（证明按 Address 重算）。

**最小间隔表**（DEC-0005 闭集第 3 项）：

- 键：请求中的 **Address**（18 字节），不是控制通道 IP:Port。
- 值：上次**接受**该 Address 的时间。
- 距上次接受 < 10s → `RateLimited`，不发 SN、不更新 Validation。
- TTL：15s（略大于 10s）。容量建议 65536；插入时删过期，仍满则驱逐最旧。不得改键。

`Distance` 钳到 ≤2700s 后重签 Validation，在 QUIC 上返回，再发 SN。

#### 4.2 Key32 发送窗（DEC-0005 闭集第 2 项）

一次 `STUN:Live` 验证通过后，Key32 只存在于该请求的处理协程。用于构 SN 与验客户端回包。有效回包或 8 次发完即释放。不跨请求复用，不进入进程级「会话」表。

发送间隔（ms，硬编码表，可截前缀）：100, 200, 400, 800, 1600×4。从 Listener 同一 IP:Port 发出。收到有效客户端 SN（tag=`Client@STUN:Live`）即停。未收到则发完自然结束，无额外超时。

#### 4.3 服务端静默

两次 `STUN:Live` 之间，不得向该 Address 发送任何包（QUIC 重传、路径探测、Reset、SN）。被测映射在窗口内不是活跃 QUIC 连接。

共享 Listener **不得**设置 `StatelessResetKey`（否则误入的 QUIC 形包可能向 Address 发 Reset，续活映射）。应用注入的 server Transport 同样必须 key 为 nil，否则不得声称符合 `STUN:Live`。

处理循环不得把其它连接的重传发到被测 Address。

### 5. 客户端 API

```go
type LiveConfig struct {
    StartInterval time.Duration // 必填，≥10s
    Precision     time.Duration // 默认 5s；0 表示只粗测
    MaxCoarseIter int           // 0 表示不限制
    TmpN          stun2.TmpNFunc
}

type LiveKind int // NATLifetime, OpenOrFirewall, Unconverged

type LiveResult struct {
    Kind     LiveKind
    Lifetime time.Duration // Kind==NATLifetime 时为最后成功间隔
}

func RunLive(ctx context.Context, server Material, cfg LiveConfig) (LiveResult, error)
```

状态机可单步推进（预探测 / 关旧连 / 等待残留 / 等间隔 / 请求 / 收包 / 粗测更新 / 精测更新）。Runner 用库内计时跑完；`ctx` 取消则停止，不写盘。

控制连接断开：本轮无存活期，error 或 `Kind` 可区分「中止」与「测到失效」。**映射超时**用上一次成功间隔作为结果；**控制断开**不使用该间隔。


## 边界与限制

- 不要求控制通道与被测映射同 IP。
- 不把粗测进度持久化。
- 不发现节点、不换节点。
- 网关异常不在协议范围。
- 不得增加 Inquire 会话 ID 或按控制通道 IP 的 Live 会话表。


## 待决问题

无。quic-go 最低版本由 Plan 在引入依赖时选定，须满足：`Transport.StatelessResetKey`、`ReadNonQUICPacket`、`Conn.CloseWithError`、`Conn` 为结构体（v0.53+）；优先使用 `ConnectionStats`。


## 对 Plan 的约束

- 依赖 SPEC-0001、SPEC-0002。可与 SPEC-0003 并行实现服务端表与客户端状态机，但静默路径测试必须单独验收。
- TDD 顺序建议：Validation 签发/校验 → 限速表按 Address 键 → 发送间隔表 → 粗测/精测纯函数（用构想中的全部示例作表驱动）→ 关 Conn + 等待 `3*pto` → 抓包或 Transport 替身证明 `Time.0` 后无额外发送。
- 静默验收：自 `Time.0` 至本轮结束，除约定 SN 外无其它 UDP 载荷。做不到则不得声称符合 `STUN:Live`。
- `go.mod` 引入 `quic-go`（v0.53+）与（若尚未引入）`github.com/cxio/equix-cgo/puzz`。
