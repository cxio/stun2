# SPEC-0004 `STUN:Live`

## 来源追溯

- `conception/keepalive.md` 全文。
- `DEC-0001`：状态机 + Runner；一次调用一个地址族；库按流程建连与关连；不持久化粗测进度。
- `DEC-0002`：`STUN:Live.Port` / `STUN:Live` 共用信封。
- `DEC-0004`：旧路径保留 Transport，只读裸 UDP；抑制 Stateless Reset；首次 `Time.0` 在关闭残留之后；服务端禁发从观测 Conn closing 至下次被接受的 `STUN:Live`（含首次窗）；等待用实现内部 PTO。
- `DEC-0005`：Key32 发送窗、按被测 Address 的 10s 限速。
- `DEC-0006`：可携带区间导出/注入；精测只认区间；一次调用三种模式；构造与 Runner 同一配置。
- SPEC-0001：信封、SN、Validation HMAC、常量、`LiveBounds` / `CanFine`。
- SPEC-0002：地址观测语义；本服务用 `STUN:Live.Port` 而非 `STUN:Addr` 取批条。


## 概述

规定存活期探测的载荷、静默路径、服务端短暂表，以及粗测 / 精测状态机与可携带区间。控制通道不必与被测映射同公网 IP。控制连接断开则丢弃本轮，不把上次成功间隔记为存活期。超时与间隔表见 SPEC-0001 §10。


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

`DialUDP`（或等价已连接 Socket）建 QUIC，发 `STUN:Live.Port`。`ClientAddr` 与本机源地址 `Equal` → 结束，结果为「无需测存活期」（Open Internet | UDP Firewall），不进入正式探测。本机源地址须为实际网卡通讯 IP，禁止通配地址（同 SPEC-0002）。否则暂存 `ClientAddr` 与 `Validation`。

#### 2.2 Step.1 静默旧路径（硬不变量）

DEC-0004 的取舍在此映射为步骤：

1. 对旧 `quic.Conn` 调用 `CloseWithError`（必须发出 `CONNECTION_CLOSE`），不得只 `Transport.Close()` / 本地 destroy。
2. **保留**旧 `quic.Transport`，不再对该 Transport `Dial` / `Listen` / `AddPath`。
3. 构造该 Transport 时 **`StatelessResetKey` 必须为 nil**。库创建的探测 Transport 一律不设此字段。应用注入的 Transport 若已设置 key，不得用于 `STUN:Live` 旧路径（Runner 应拒绝或要求调用方提供未设 key 的 Transport）。
4. `quic.Config.DisablePathMTUDiscovery = true`，避免额外 UDP。
5. 等待关闭残留结束（§2.3），**然后**记录首次 `Time.0`。
6. 此后旧路径只调用 `ReadNonQUICPacket()`（应用注入 Transport 时经 `PushNonQUICPacket` 投递，见 SPEC-0003 §5）。从 `Time.0` 到本轮结束，对该四元组抓包：除服务端 SN 与客户端对 SN 的回应外，不应出现其它 UDP 载荷（含 `CONNECTION_CLOSE`）。

新控制通道：新随机端口向同一节点拨号，正常 keep-alive。换网或控制连接断开：丢弃本轮，不产出存活期；若继续，从 §2.1 重新开始。

#### 2.3 关闭残留等待

quic 实现对已关闭连接的 `CONNECTION_CLOSE` 重传窗口为 `3*PTO`。等待方式：

1. 优先使用实现导出的内部 PTO（须含 RFC 9002 的 `max_ack_delay`）。若所选模块导出 `ConnectionStats` 且其中有 PTO 字段，在 `CloseWithError` **之前**读取该值。
2. 禁止自拼 `SmoothedRTT + 4*MeanDeviation` 作为 PTO（缺 `max_ack_delay`，可能短于真实关闭窗）。
3. `CloseWithError` 之后等待 `max(3*pto, 1s)`（可被 `ctx` 取消）。`pto` 不可用时等待固定 `3s`。
4. Plan 在引入依赖后核对符号与 **server Listener** 上 closing 是否为收包触发；不得静默跳过等待。若实现会定时重传 `CONNECTION_CLOSE`，服务端须在收到 CC 后立即销毁该 Conn，保证不再写出。

后续每一轮的 `Time.0` 为对 SN 的**最后一次**客户端回包时刻，不再加关闭残留。

例外：若某版本在无连接、key 为 nil 的 Transport 上仍自发 UDP，则记录为被迫 `UDPConn.ReadFrom` 的例外路径，但仍须先关 Conn、等残留、再停 Transport，并满足 §2.2 抓包验收。默认路径不拆栈。

#### 2.4 Step.2 请求与收包

到达探测间隔后，在新 QUIC 上发 `STUN:Live`。客户端自**发出该 `STUN:Live` 请求**起 10s 内若无有效服务端 SN，判定映射已失效。不以收到新 Validation 为起点：服务端发完 Validation 即发 SN，裸 UDP 的 SN 可能先期抵达。

收到服务端 SN（`VerifySN`，tag=`Server@STUN:Live`，Key=本轮 Key32）后立即回一个客户端 SN（tag=`Client@STUN:Live`，同一 Key32，新 Rnd16/TmpN）。最多回 8 次（与服务端发送上限一致）。每次有效回包更新 `Time.0`。

`探测间隔` = 本次 `Time.0` 到发出下一次 `STUN:Live` 的时长。

### 3. 粗测与精测

间隔单位与比较用 `time.Duration`。下列规则全程适用（含精测各点）：

- 起始间隔 `Start` **必填**，`< 10s` 为配置错误。
- 每一次探测的静默间隔不得低于 10s。本库不报告短于 10s 的存活期。
- 算出的 `next` 若 ≥ 10s，按该值测。若 < 10s：取 **10s 本身再测一次**；该次再失败则停止——有 `lastSuccess` 则以其为存活期，否则 error（无法在 ≥10s 间隔上测得存活期）。
- `Start=10s` 且该次已失败时，回退必低于 10s，**不再把 10s 测第二遍**，直接按上一句「再失败」处理（无 `lastSuccess` → error）。
- **不得**把间隔钳在 10s 上反复迭代直到次数上限。
- 精测精度 `Precision` 可配，默认 5s，是二分步长的**收敛终止误差**（当本轮 `|step| < Precision` 时做完该次测试即停），不是「可测 5s 量级的存活期」，也不是测得值与真实 NAT 超时的误差上限。
- 每一次**失败**后的再测必须从 §2.1 重建映射。成功后的下一间隔仍在同一轮（同一旧映射、同一控制通道）上继续 Step.2。

**粗测：** 记 `lastSuccess`、`lastFail`、`step`。第一次探测间隔为 `Start`。

- 成功：`lastSuccess = current`；`step = current`；`next = 2*current`。
- 失败：`raw = current - step/2`（首次即失败时视 `step = Start`，故 `raw = Start/2`）；`step = step/2`；`lastFail = current`。再按本节开头的下限规则得到 `next` 或停止。
- 若 `next` 将超过 40 分钟则改测 **40 分钟**。40 分钟成功则结果为 40 分钟（上限，实际可能更长）；失败则按失败规则回退。
- **结束（正常）：** 出现「失败 → 成功」后，结果为最后一次成功间隔。
- **结束（下限停）：** 因 `next < 10s` 而按 10s 补测仍失败，或 `Start=10s` 首次失败：有 `lastSuccess` 则取之，否则 error。
- **结束（迭代上限）：** 可配置次数上限（默认不限制或由调用方设）。到达上限仍无「失败→成功」则取 `lastSuccess`；若从未成功，返回 error（配置过高或异常，换节点由应用决定）。已有 `lastFail` 时 `Kind=NATLifetime`，`Bounds` 可注入另一次精测；从未失败则为 `Unconverged`。

**精测**（可与粗测不同服务器；必须从 §2.1 起新的一轮）：

输入 `stun2.LiveBounds`：`n = LastSuccess`、`M = LastFail`。`CanFine` 为假则不能精测（无 `LastFail`、或其未严格大于 `LastSuccess`、或越出 §3 合法范围）。`D = M-n`。`step = D/2`，`current = n + step`（`n ≥ 10s` 故 `current ≥ 10s`）。

```
循环：
  测试 current
  若成功：lastSuccess = current
  若失败且 current == 10s：结束（结果为 lastSuccess；精测从未成功则为 n）
  若 step < Precision：结束
  step = step / 2
  成功则 current += step，失败则 current -= step
  若 current < 10s：current = 10s（按 10s 再测一次，适用上段「再失败则停」）
```

与构想示例一致：会执行那次 `step < Precision` 的测试，再停。结果为精测过程中最后一次成功；若精测从未成功，结果为 `n`。

粗测因一直成功触达上限、没有 `M` 时，不能进入精测；Runner 返回粗测上限结果并标明未收敛（`Kind=Unconverged`，`Bounds.LastFail` 为零）。

粗测结束后的区间必须写入结果的 `Bounds`（`LastSuccess` / `LastFail`），即使本次调用不再做精测。同机先粗后精（`Precision>0` 且未注入区间）时，粗测若 `CanFine` 则立刻从 §2.1 新开精测，不把中间区间交还调用方；若不能精测则按上句返回未收敛。

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

禁发范围见 DEC-0004 第 4 条。实现要点：

- 不得向该 Address 发送任何包（QUIC 重传、路径探测、Reset、SN、定时 `CONNECTION_CLOSE`），唯一例外为当场回一个 `CONNECTION_CLOSE`。
- closing 重传须为收包触发；不得依赖 draining 定时器对该 Address 继续发包。被测映射在窗口内不是活跃 QUIC 连接。不为此新增短暂表。
- 共享 Listener **不得**设置 `StatelessResetKey`。应用注入的 server Transport 同样必须 key 为 nil，否则不得声称符合 `STUN:Live`。该端口上所有 QUIC 连接因此没有 Stateless Reset。
- 处理循环不得把其它连接的重传发到被测 Address。

### 5. 客户端 API

区间类型与可否精测在根包（SPEC-0001 §11）：

```go
// stun2
type LiveBounds struct {
    LastSuccess time.Duration // n；零值表示尚无成功
    LastFail    time.Duration // M；零值表示尚无失败
}

// CanFine 当且仅当 LastSuccess ≥ 10s、LastFail > LastSuccess、且 LastFail ≤ 40 分钟。
func CanFine(b LiveBounds) bool
```

`LiveBounds` 不含服务器身份。应用跨调用、跨服务器持有；库不写盘、不在库内记住上次调用的区间，也不校验区间来自哪台服务器。

```go
type LiveConfig struct {
    StartInterval time.Duration     // 从粗测起必填，≥10s；只精测时忽略，不得当作 n/M
    Precision     time.Duration     // 见下表
    MaxCoarseIter int               // 0 表示不限制；只精测时忽略
    TmpN          stun2.TmpNFunc
    Bounds        *stun2.LiveBounds // nil = 从粗测起；非 nil = 只精测，须 CanFine
}

type LiveKind int // NATLifetime, OpenOrFirewall, Unconverged

type LiveResult struct {
    Kind     LiveKind
    Lifetime time.Duration    // Kind==NATLifetime 或 Unconverged 时为最后成功间隔
    Bounds   stun2.LiveBounds // 本次结束时的区间；OpenOrFirewall 为零值
}

func NewLive(server Material, cfg LiveConfig) (*LiveMachine, error)
func RunLive(ctx context.Context, server Material, cfg LiveConfig) (LiveResult, error)
```

`NewLive` 与 `RunLive` 使用同一份 `LiveConfig`，在构造时校验：

| `Bounds` | `Precision` | 行为 |
|----------|-------------|------|
| `nil` | `0` | 只粗测。`StartInterval` 必填且 ≥10s，否则配置错误 |
| `nil` | `>0` | 同机先粗后精。粗测结束后若 `CanFine` 则从 §2.1 新开精测；否则返回 `Unconverged` |
| 非 `nil` 且 `CanFine` | `0` | 只精测，精度用默认 5s。忽略 `StartInterval` 与 `MaxCoarseIter` |
| 非 `nil` 且 `CanFine` | `>0` | 只精测，用该精度。忽略 `StartInterval` 与 `MaxCoarseIter` |
| 非 `nil` 且 `!CanFine` | 任意 | 配置错误，不开始探测 |

`StartInterval` 不是 `n` / `M` 的替代。只精测不得要求调用方再填起始间隔。

`Material` 见 SPEC-0003 §5。一次构造 / 一次 `RunLive` 绑定一台服务器、一个地址族。

`LiveMachine` 可单步推进（预探测 / 关旧连 / 等待残留 / 等间隔 / 请求 / 收包 / 粗测更新 / 精测更新）。`Bounds` 非空时不进入粗测更新，算法从精测起，I/O 仍从 §2.1 起。`RunLive` 即 `NewLive` 后循环 `Step` 至结束。Runner 用库内计时跑完；`ctx` 取消则停止，不写盘。测试可注入时钟（同 SPEC-0003）。应用注入 `Transport` 时，`LiveMachine` 与 Runner 暴露与 SPEC-0003 相同的 `PushNonQUICPacket`。

```go
func (m *LiveMachine) Step(ctx context.Context) (done bool, err error)
func (m *LiveMachine) Result() LiveResult
```

`Step` 返回 `done==true` 后 `Result` 有效。配置错误在 `NewLive` / `RunLive` 返回 `error`，不产出结果。

`LiveResult.Bounds`：

- `OpenOrFirewall`：零值。
- 只粗测结束：`LastSuccess` 为最后成功间隔（同 `Lifetime`）；有过失败则填 `LastFail`，否则为零。`CanFine(Bounds)` 为真时应用可另一次调用注入该值做精测。
- 精测结束（含同机先粗后精）：`LastSuccess` 为精测最后成功（同 `Lifetime`；精测从未成功则为注入的 `n`）；`LastFail` 为精测过程中最后失败，若精测从未失败则保留进入精测时的 `M`。
- `Unconverged`：`LastSuccess` 为上限上的最后成功，`LastFail` 为零。

控制连接断开：本轮无存活期，error 或 `Kind` 可区分「中止」与「测到失效」。**映射超时**用上一次成功间隔作为结果；**控制断开**不使用该间隔。


## 边界与限制

- 不要求控制通道与被测映射同 IP。
- 不把粗测进度持久化到磁盘或库内跨调用状态；区间由 `LiveResult.Bounds` 交还应用。
- 不得用 `StartInterval` 注入粗测结果。
- 不发现节点、不换节点。
- 网关异常不在协议范围。
- 不得增加 Inquire 会话 ID 或按控制通道 IP 的 Live 会话表。


## 待决问题

无。quic 模块路径与版本由 Plan 在引入依赖时选定，须满足 DEC-0004 与 §2.3 / §4.3（含 server Listener 路径）。


## 对 Plan 的约束

- 依赖 SPEC-0001、SPEC-0002。可与 SPEC-0003 并行实现服务端表与客户端状态机，但静默路径测试必须单独验收。
- TDD 顺序建议：Validation 签发/校验 → 限速表按 Address 键 → 发送间隔表 → `CanFine` 与 `LiveBounds` 零值 → 粗测/精测纯函数（以 `LiveBounds` 为输入，用构想中的全部示例作表驱动；含 `Start=15s` 失败后按 10s 补测一次、该次再失败则停；`Start=10s` 失败直接 error、不二次测 10s；步进逻辑不得只写在状态机闭包里）→ `NewLive` / `RunLive`：`Precision=0` 只粗测时 `Result.Bounds` 带出 `LastFail`（若有）；注入 `CanFine` 区间则跳过粗测、从 §2.1 做精测；`!CanFine` 的区间为配置错误；未注入 `Bounds` 时无论 `StartInterval` 为何都走粗测，不得把起始间隔解释为精测输入 → 关 Conn + 等待 `max(3*实现PTO, 1s)` → 抓包或 Transport 替身证明 `Time.0` 后无额外发送。
- 静默验收：自 `Time.0` 至本轮结束，除约定 SN 外无其它 UDP 载荷；关 Conn 后到首次 SN 前，服务端→该 Address 在 `Time.0` 之后包数为 0（含 `CONNECTION_CLOSE`）。做不到则不得声称符合 `STUN:Live`。
- `go.mod` 引入的 quic 模块路径与版本由 Plan 选定（须满足 DEC-0004：`StatelessResetKey` 可 nil、`ReadNonQUICPacket`、`CloseWithError`、实现内部 PTO、server Listener closing 收包触发或收到 CC 后立即停写）；另引入（若尚未引入）`github.com/cxio/equix-cgo/puzz`。
