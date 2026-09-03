# DEC-0001 三层职责与包边界

## 背景 （Context）

README 把交付物分成基础库、客户端、服务器，构想没有说谁持有 QUIC 连接、谁读裸 UDP、谁驱动最长可达一小时的 `STUN:Live` 循环。节点发现、ALPN `h3`、ClientHello 工作量认证已划给 p2p / wTLS / stun2p。构想写了源服务器维护受托连接池、客户端用 `Equi-X` 算 Cone 挑战，但没说池的实现和 Equi-X 算法落在本库还是应用/外库。没有这份决策，Spec 无法定包路径、公开 API 和 I/O 所有权。

## 决策 （Decision）

Go 模块仍为 `github.com/cxio/stun2`，公开包三个：

| 包 | 职责 | 不含 |
|----|------|------|
| `stun2` | SN 构造与验证、Validation / Challenge 的 HMAC 与时间窗、控制信封编解码、IPv4-mapped 规范化、判定矩阵等纯函数、协议常量；Cone 挑战调用 `github.com/cxio/equix-cgo/puzz` | 网络 IO、计时、重试、节点发现、Equi-X 算法实现 |
| `stun2/client` | Addr 预探测、Cone 正式探测、Live 循环的状态机与 Runner | 节点发现、多源聚合、UDP Blocked、换节点 |
| `stun2/server` | Addr / Cone / Live 请求处理，通路 / NewPort / NewHost，挑战与 Validation 的签发校验续期，DEC-0005 允许的短暂表 | 受托节点发现、拨号与连接池实现；ClientHello 工作量认证 |

允许 `internal/` 放置不导出的共享实现。不拆成多个 Go 模块。

切点：

1. **连接所有权。** 应用注入连接材料（对端地址、TLS / SPKI、可选已有 `quic.Transport`）。库按 Cone / Live 流程创建和关闭探测所需的 Socket 与 `quic.Conn`。库不发现节点，不做握手期 Equi-X。
2. **裸 UDP 读取权。** 库自己创建的 Transport 由库独占 `ReadNonQUICPacket()`。应用注入的 Transport 仍由应用读取，再把非 QUIC 包交给库。
3. **驱动模型。** 状态机是 `stun2/client` 的核心（可单步推进）。另提供带 `context.Context` 的 Runner，用库内计时把一轮探测跑完。应用默认走 Runner；需要测试、暂停或自行调度时推进状态机。库不把粗测进度持久化到磁盘。
4. **一次调用范围。** 一次 API 调用绑定一条连接、一个地址族，只产生该族结果。双栈由调用方跑两遍。库不合并 IPv4 / IPv6。
5. **多源与 Exclist。** 库只返回单次探测结果。不维护近期连过的 IP 列表。跨服务器综合评估由应用做。
6. **受托池与本机第二 IP。** 受托连接池由应用提供。库只定义调用接口（抽选节点、在已有连接上发 `STUN:Cone.Challenge` / `STUN:Cone.NewHost`）；接口的实现（发现、拨号、保活、池的维护）由应用负责。源服务器用本机新 IP 代替 NewHost 是可选部署能力，不是默认路径。
7. **Equi-X 与 TmpN。** 库只在 Cone 挑战路径上使用 Equi-X（客户端 `puzz.Solve` / `puzz.SolveContext`，源服务器与受托 `puzz.Verify`）。算法由 `github.com/cxio/equix-cgo/puzz` 实现，本库只组装输入并调用，不实现 Equi-X。握手工作量认证仍属上层。TmpN 默认用 CSPRNG 生成 16～1024 字节，并提供可选注入接口。
8. **配置分档。** 构想标明*不可配置*的为硬编码；标明可配置的由库给默认值、调用方可覆盖；粗测起始间隔无默认值，调用方必填；每一次静默间隔硬性下限 10s（含失败回退；算出值低于 10s 则按 10s 测一次，见构想）。Inquire 收集 7s 与客户端等待 11s 亦为硬编码。
9. **QUIC 连接迁移。** 探测用连接禁止 path migration，避免 `STUN:Addr` 观测到的地址与 SN 所用 UDP 四元组分家。

## 理由 （Rationale）

节点发现与首包认证已在构想里划出本库；Cone 正式探测必须新建 `ListenUDP`，Live 必须关旧 Conn 再开新端口，所以「每条 Conn 都由应用创建」会把协议步骤漏到应用里。注入材料、库按流程建连，能同时满足这两点。

受托池同属节点发现与连接生命周期，库自建池会把发现/拨号拉回来；只定义接口，让 `stun2/server` 能抽选并委托，而不拥有连接。Cone 的 Equi-X 已有独立实现，本库只固定输入拼接（`Challenge || Address || KeyHash`）再调用；算法放进本库会重复维护 cgo 绑定，也和握手期 Equi-X 混在一起。

同一 `quic.Transport` 只有一个非 QUIC 读取点。库创建的探测 Socket 没有第二位读者，独占最干净；应用已有的 p2p Transport 不能被库抢走读取权，故按所有权拆。

Live 可能数十分钟，必须能取消；纯状态机便于测，Runner 避免每个调用方重写定时器。一次调用一个地址族，与 `pubaddr.md`「要测 IPv4 必须显式走 IPv4」一致。构想已删 Exclist，并写明综合评估不是本协议职责，这里写成「明确不做」，避免 Spec 加回来。

## 影响 （Consequences）

- Spec 按三个包列导出符号；应用负责节点表、TLS 材料和双栈是否跑两遍。
- Spec 为受托池定义调用接口，不提供默认实现；应用注入实现后，`stun2/server` 才能做 Inquire 抽选与 NewHost 委托。
- `go.mod` 依赖 `github.com/cxio/equix-cgo/puzz`；Cone 客户端 `Solve` / `SolveContext` 与服务端/受托 `Verify` 均为其调用方。
- 注入 Transport 的调用方必须把非 QUIC 包 push 进库，否则 Cone / Live 收不到 SN。
- 禁止迁移后，控制通道地址在一轮探测内视为稳定；换网表现为连接断开（Live 丢弃本轮，见 `keepalive.md`）。

## 构想层依据 （Conception References）

- `conception/pubaddr.md`：双栈须显式选路；控制面在已有 QUIC 上。
- `conception/conelevel.md`：技术栈与 ALPN / 首包认证属上层；UDP Blocked 为应用层；综合评估不是本协议职责；TmpN 可外部定制；正式探测须 `ListenUDP`；Passage / Inquire 各拨任意一台；源服务器维护受托连接池并从中抽选；Cone 挑战用 `puzz.Solve` / `puzz.Verify`。
- `conception/keepalive.md`：客户端主导节奏；不要求控制通道与被测映射同公网 IP。
- README：基础库 / 客户端 / 服务器三分。

## 开放问题 （Open Questions）

无。
