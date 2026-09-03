# SPEC-0003 `STUN:Cone`

## 来源追溯

- `conception/conelevel.md` 全文。
- `DEC-0001`：连接所有权、裸 UDP 读取权、状态机 + Runner、一次调用一个地址族、受托池只定义接口、正式探测必须 `ListenUDP`。
- `DEC-0002`：统一信封；通路失败只关连接。
- `DEC-0003`：`ConeKind` / `ConeResult` 类型拆分；池须支持持续抽选；不可达不暴露内部原因。
- `DEC-0005`：源服务器仅允许 Challenge→受托 表；受托按 Target 单一发包去重；SN 不设重放缓存。
- SPEC-0001：信封、SN、Challenge HMAC、Equi-X 调用、常量。
- SPEC-0002：`GetAddr`。


## 概述

规定 Cone 预探测、通路、委托询问、正式探测的载荷、两端行为、受托池接口，以及一次调用返回的 `ConeResult`。综合评估、换节点、`UDP Blocked` 不在库内。超时与包数见 SPEC-0001 §10。


## 规格正文

### 1. 一次调用的终态

`stun2/client` 一次 Cone 探测返回 `ConeResult`（无 `UDP Blocked`、无 `Unknown`）。前置两态可提前给出并结束调用；矩阵五态只在正式探测得出。

| 值 | 类型 | 阶段 |
|----|------|------|
| `SymLike` | 仅 `ConeResult` | 预探测：不少于配置数的 `STUN:Addr` 中，端口不全相同；提前终止 |
| `QUICOnly` | 仅 `ConeResult` | Passage：确认后超时未收到有效 Passage SN；提前终止 |
| `FullCone` / `RC` / `PRC` / `OpenInternet` / `UDPFirewall` | `ConeKind` ⊂ `ConeResult` | 正式探测矩阵 |

`ConeKind` 是根包 `ClassifyCone` 的值域，**不含** `SymLike` / `QUICOnly`。正式探测前的其它失败（拨号、Inquire 受托不足、Equi-X 无解、控制面 Status≠0、ctx 取消）用 `error` 返回，不伪造类型，也不把提前终态放进 `error`。

`ClassifyCone(newPort, newHost, localEqual)`：

| NewPort | NewHost | 与本机全等（NewMap） | 结果 |
|:---:|:---:|:---:|------|
| * | Y | N | FullCone |
| Y | N | N | RC |
| N | N | N | PRC |
| * | Y | Y | OpenInternet |
| * | N | Y | UDPFirewall |

NewPort / NewHost 在超时前零有效包、校验失败、超时，一律视为该路径不可达（N）。不向调用方暴露这三种内部原因。NewHost 超时且 NewMap.N 不单独定论，由 NewPort 行判定 `RC` / `PRC`。NewHost 先到且已能判定时，可提前结束 NewPort 等待。

### 2. 方法载荷

Version 均在信封中，不再重复。

**`STUN:Cone.Passage` 请求：** `Key32`（32 字节）。响应：空。随后服务器在同一 UDP 四元组上发 2 个 Passage SN（间隔 100–300ms 均匀随机）。

**`STUN:Cone.Inquire` 请求：** 空。响应：

```
Count       u8          2 或 3
重复 Count 次：
  Challenge  u16+字节
```

**`STUN:Cone.Challenge`（源→受托）请求：** 空。响应：Challenge 原始字节（读到 FIN）。受托用当前 QUIC 对端作 `ServAddr` 签发。

**`STUN:Cone` 请求：**

```
Key32        32 字节     与 Passage 的 Key32 不同；当场生成
Count        u8          2 或 3
重复 Count 次：
  Challenge  u16+字节
  Solution   16 字节     soln.Solution.MarshalBinary()（equix.Solution；非 puzz.Solution 的 24 字节）
  Nonce      u64 大端     soln.Nonce
```

响应：空。随后源服务器并发 NewPort 与 NewHost。

**`STUN:Cone.NewHost` 请求：**

```
KeyHash      32 字节     SHA256(Key32)
Target       18 字节
Challenge    u16+字节
Solution     16 字节     soln.Solution.MarshalBinary()（equix.Solution；非 puzz.Solution 的 24 字节）
Nonce        u64 大端     soln.Nonce
```

响应：空。随后受托向 Target 发 NewHost SN（默认 3 个，间隔 100–500ms 均匀随机）。

### 3. 客户端流程

连接材料与裸 UDP 读取权见 DEC-0001。禁止 `AddPath`。库创建的 Transport 由库独占 `ReadNonQUICPacket()`；应用注入的 Transport 由应用读，再调用 `PushNonQUICPacket` 投递给库（§5）。

#### 3.1 预探测

- 复用**同一**底层 `UDPConn`（及同一 `quic.Transport`）向不少于 `MinAddrResults`（默认 3）台服务器并发或紧挨着请求 `STUN:Addr`。
- 成功数不足配置值：返回 error。
- 端口不全相同 → `SymLike`，结束。
- 全部相同：视为 `非 Sym-Like`，进入通路确认。

#### 3.2 通路

- 向任意一台拨号（可与 Inquire 不同源）。发送 Passage（新 Key32）；裸 UDP 读循环须在发送前启动（`ReadNonQUICPacket` 首次调用前的到达包会被丢弃）。
- 超时从**收到确认**起 4s。收到有效 Passage SN（`VerifySN`，source=0，`domainTag=STUN:Cone`，Key=该 Key32）即通过。
- 超时：关 QUIC，返回 `QUICOnly`。不发额外控制请求。服务端仍按计划发完 2 个包，客户端已关则丢弃。

#### 3.3 询问与创建映射

- 向任意一台（源服务器）发 Inquire。自**发出该请求**起 11s 内须收到 Status=0 且 Count∈{2,3} 的挑战集；超时或 `InsufficientTrustees` 等 Status≠0 为 error，不伪造 `ConeResult`。
- **必须** `net.ListenUDP` 新未连接 Socket（不可 `DialUDP`），在其上建到**该源服务器**的新 QUIC，再 `GetAddr`，得到 `ClientAddr`，并开始读非 QUIC 包。
- `localEqual`（NewMap）由新映射与新 Socket 本机地址比较得出（正式探测与预探测映射相互独立；预探测不做本机比较）。本机地址须为实际网卡通讯 IP，禁止通配地址（同 SPEC-0002）。

#### 3.4 求解与请求

对每份 Challenge：

```
seed = SHA256(Challenge || ClientAddr18 || SHA256(Key32))
soln, err = stun2.SolvePuzzle(ctx, seed)   // SPEC-0001 §8
```

将 `[Challenge, soln.Solution 16B, soln.Nonce]` 组成 Proofs，发送 `STUN:Cone`。回包超时从**发送完该请求**起，默认 6s，可配置。

#### 3.5 收包校验

对每个入站 UDP：

1. 长度 64–1072；`VerifySN` 用 `domainTag=STUN:Cone`。
2. NewHost（低 2 位 = 2）：`Key = SHA256(Key32)`；若 `SourceIP == ServIP` 则丢弃（防源服务器假冒）。
3. NewPort（低 2 位 = 1）：`Key = Key32`；若 `SourcePort == ServPort` 或 `SourceIP != ServIP` 则丢弃。
4. Passage 包在正式探测阶段忽略。

任一路径收到至少一个有效包即记为 Y。

### 4. 服务端

#### 4.1 受托池接口（无默认实现）

```go
type Delegate interface {
    PeerAddr() stun2.Addr          // 源服务器用来索引 Challenge→受托
    Challenge(ctx context.Context) (challenge []byte, err error)
    NewHost(ctx context.Context, req NewHostRequest) error
}

type TrusteePool interface {
    // Pick 随机抽选至多 n 个当前可用、且 PeerAddr 不在 exclude 中的受托。
    // 返回 0..n 个；不足 n 不报错。仅当池不可用（未注入）时返回 error。
    Pick(n int, exclude []stun2.Addr) ([]Delegate, error)
}
```

实现负责发现、拨号、保活。库只在已有连接上发 `STUN:Cone.Challenge` / `STUN:Cone.NewHost`。

#### 4.2 Inquire

池为 nil 或 `Pick` 返回 error：立即 `InsufficientTrustees`。

否则在截止时刻 `now+7s` 内持续抽选并并发 `Challenge`：

1. 已收集 **3** 份：立即向客户端返回（不必等到 7s）。
2. 对尚未尝试（exclude = 已成功 + 已失败/拒绝 + 仍在途）的节点 `Pick`，建议每次 `n = 3-已收集数`（也可一次多抽以竞速）；对返回的受托发 `Challenge`。
3. `Pick` 返回空且无在途请求：不再抽选，等待截止（或已有在途则等其结束）。
4. 到达 7s：已有 **≥2** 份则返回已收集的 2 或 3 份；否则 `InsufficientTrustees`。
5. **禁止**在满 2 份但未满 3、且未到截止时提前返回。

每写入一份 Challenge，在短暂表登记 `Challenge → Delegate`（或对等的受托寻址信息）。

#### 4.3 Challenge 表（DEC-0005 闭集第 1 项）

- 键：Challenge 完整字节；不按客户端地址索引。
- 值：对应 `Delegate`。
- TTL：可配置，默认 2 分钟（与挑战有效期相同）。
- `STUN:Cone` 用过即删（该请求里出现的每一份）。
- 容量建议 4096；插入时先删过期，仍满则拒新 Inquire（`InsufficientTrustees`）或驱逐最旧过期项。
- 进程重启后表空，进行中的 Cone 失败，客户端换节点或重走 Inquire。

#### 4.4 `STUN:Cone` 处理

1. 解析 Count∈[2,3]，否则 `InvalidPayload`。
2. `ClientAddr = Normalize(conn.RemoteAddr())`。
3. 对每个 Proof：查表得受托；无记录或 Challenge / Equi-X / `VerifyPuzzle(SHA256(Challenge||ClientAddr18||SHA256(Key32)), &puzz.Solution{Nonce, Solution})` 失败 → `VerifyFailed`。
4. 成功则删表项，回空响应。
5. **NewPort**（可与 NewHost 并发）：保持当前通讯 IP 不变，从本机新随机端口向 `ClientAddr` 发 4 个 SN，`source=1`，`Key=Key32`，间隔 100–400ms。
6. **NewHost**：对每个已验证 Proof 调对应 `Delegate.NewHost`。某受托失败只影响该路径，不把整次请求改成错误（客户端按是否收到包判定）。

源服务器用本机另一 IP 代替 NewHost 是可选部署，不是默认路径；若启用，SN 仍用 `source=2` 且 `Key=SHA256(Key32)`，客户端 `SourceIP != ServIP` 检查仍适用。

#### 4.5 受托

收到 Challenge：按 SPEC-0001 §7 签发，无存储。
收到 NewHost：用**当前** QUIC 对端作 `ServAddr` 验 Challenge；`VerifyPuzzle(SHA256(Challenge||Target||KeyHash), &puzz.Solution{Nonce, Solution})`；失败回 `VerifyFailed`。通过则查 Target 去重表（§4.6）：首次接受即向 Target 发 SN（`source=2`，`Key=KeyHash`，默认 3 个，间隔 100–500ms）；重复到达静默丢弃，不发包，响应仍为空成功。

Passage：回确认后 6s 内发完 2 个包。`Key=请求 Key32`，`source=0`。

#### 4.6 Target 单一发包去重表（DEC-0005 闭集第 4 项）

- 键：Target（18 字节线格式）；不按 Challenge 或源服务器地址索引（换 Challenge 重放同一目标同样被抑制）。
- 值：到期时间。
- TTL：与受托自己的挑战有效期（Distance，可配置）相同。
- 重复到达：静默丢弃，不发包，响应同正常（空成功）。
- 容量建议 4096；插入时先删过期，仍满则驱逐最早到期项。
- 表只记录「该 Target 已发过包」，不缓存 SN 报文本身。


### 5. 客户端 API

核心是可单步推进的状态机；另提供带 `context.Context` 的 Runner 跑完整一次探测。应用默认走 Runner。库不把进度持久化到磁盘。

```go
type ConeConfig struct {
    MinAddrResults int           // 默认 3
    ProbeTimeout   time.Duration // 默认 6s
    TmpN           stun2.TmpNFunc
}

type Material struct {
    Server    net.Addr
    TLS       *tls.Config
    Transport *quic.Transport // 可选；非空则由应用 Push 裸 UDP
}

type ConeResult int // SymLike, QUICOnly, 以及与 ConeKind 对应的五态；不是 ConeKind

func RunCone(ctx context.Context, preProbe []Material, passage, inquire Material, cfg ConeConfig) (ConeResult, error)
```

`RunCone` 不得返回 `ConeKind`。`SymLike` / `QUICOnly` 在对应阶段直接作为 `ConeResult` 返回并结束调用。

`passage` / `inquire` 若零值，使用 `preProbe[0]`。`preProbe` 必须指向同一本地端口上的材料（同一 Transport 或库为此次预探测建的共享 `ListenUDP`）。

应用注入 `Transport` 时，状态机与 Runner 均暴露如下投递入口；库按当前会话的 domainTag 与 Key 校验，非本会话包静默丢弃：

```go
// pkt 为完整 UDP 载荷，from 为发送源地址；线程安全。
PushNonQUICPacket(pkt []byte, from net.Addr)
```

状态机阶段建议：`PreProbe → Passage → Inquire → Map → Prove → Wait → Done`。测试通过注入事件推进，不依赖真实时钟时可注入时钟。

每个并发 Cone 必须使用不同本地端口，避免 SN 混淆。


## 边界与限制

- 不维护 Exclist，不合并多源结果，不在库内换节点重试 Passage。
- 不判定 `UDP Blocked`。
- 不实现受托发现与连接池。
- 不实现 Equi-X 算法。


## 待决问题

无。


## 对 Plan 的约束

- 依赖 SPEC-0001、SPEC-0002。
- TDD 顺序建议：Challenge 签发/校验 → Equi-X 往返（cgo）→ SN 来源位与假冒过滤 → `ClassifyCone`（五态）→ `Pick` 在 exclude 后可返回 0 个且不报错 → 服务端 Inquire 收集（满 3 立即返回；7s 超时且 2 份成功；满 2 未到截止不得返回）→ 客户端 Inquire 11s 超时为 error → 客户端状态机（`SymLike`/`QUICOnly` 提前终止；替身 Transport / 注入包）→ Runner（返回 `ConeResult`）。
- 正式探测路径的测试必须使用未连接 UDP（或模拟其「接受未知源 IP」的行为）；禁止用已 `DialUDP` 的替身冒充正式探测。
- 受托池用假对象：记录 `Challenge` / `NewHost` 调用次数与参数。
