# DEC-0001 三层职责与包边界

## 背景 （Context）

README 把交付物分成基础库、客户端、服务器。构想没有规定：谁持有 QUIC 连接、谁读裸 UDP、谁驱动最长可达一小时的 `STUN:Live`、受托池与 Equi-X 算法落在本库还是应用。节点发现、ALPN `h3`、ClientHello 工作量认证已划给 p2p / wTLS / stun2p。没有这份决策，Spec 无法定包路径、公开 API 和 I/O 所有权。

## 决策 （Decision）

Go 模块 `github.com/cxio/stun2`，公开包三个，不拆多模块。允许 `internal/` 放不导出实现。

| 包 | 职责 | 不含 |
|----|------|------|
| `stun2` | 编解码与纯函数：SN、HMAC/时间窗、信封、地址规范化、判定矩阵、Live 区间、协议常量；Cone 挑战调用 `github.com/cxio/equix-cgo/puzz` | 网络 IO、计时、重试、节点发现、Equi-X 算法 |
| `stun2/client` | Addr 预探测、Cone 正式探测、Live 循环的状态机与 Runner | 节点发现、多源聚合、UDP Blocked、换节点 |
| `stun2/server` | Addr / Cone / Live 处理；通路 / NewPort / NewHost；挑战与 Validation 的签发校验续期；DEC-0005 允许的短暂表 | 受托发现、拨号与连接池；ClientHello 工作量认证 |

切点：

1. **连接所有权。** 应用注入连接材料（对端、TLS / SPKI、可选已有 `quic.Transport`）。库按 Cone / Live 流程创建和关闭探测所需的 Socket 与 `quic.Conn`。库不发现节点，不做握手期 Equi-X。
2. **裸 UDP 读取权。** 库自己创建的 Transport 由库独占 `ReadNonQUICPacket()`。应用注入的 Transport 仍由应用读取，再把非 QUIC 包交给库。
3. **驱动模型。** `stun2/client` 以可单步推进的状态机为核心，另提供带 `context.Context` 的 Runner。应用默认走 Runner；测试、暂停或自行调度时推进状态机。库不把粗测进度持久化（不写盘、不跨进程、不在库内记住上次调用的区间）。粗测/精测区间作为返回值导出、由应用跨调用持有，见 DEC-0006。
4. **一次调用范围。** 一次 API 调用绑定一条连接、一个地址族。双栈由调用方跑两遍。库不合并 IPv4 / IPv6。
5. **多源。** 库只返回单次探测结果。不维护近期连过的 IP（构想已删 Exclist）。跨服务器综合评估由应用做。
6. **受托池与本机第二 IP。** 受托连接池由应用提供。库只定义调用接口（抽选、在已有连接上发 `STUN:Cone.Challenge` / `STUN:Cone.NewHost`）。源服务器用本机新 IP 代替 NewHost 是可选部署，不是默认路径。
7. **Equi-X 与 TmpN。** 仅 Cone 挑战路径使用 Equi-X（客户端 `puzz.Solve` / `puzz.SolveContext`，源服务器与受托 `puzz.Verify`）。本库组装输入并调用，不实现算法。握手工作量认证属上层。TmpN 默认 CSPRNG，并提供可选注入接口。
8. **配置分档。** 构想标明不可配置的硬编码；标明可配置的由库给默认值、调用方可覆盖。从粗测开始的调用，起始间隔无默认值、调用方必填。只精测时必填可携带区间，不要求起始间隔，见 DEC-0006。静默间隔硬性下限见构想。
9. **QUIC 连接迁移。** 探测用连接禁止 path migration。

## 理由 （Rationale）

节点发现与首包认证已划出本库；Cone 正式探测必须新建 `ListenUDP`，Live 必须关旧 Conn 再开新端口——若「每条 Conn 都由应用创建」，协议步骤会漏到应用。注入材料、库按流程建连，同时满足这两点。

受托池同属节点发现与连接生命周期；库自建池会把发现/拨号拉回来。Cone Equi-X 已有独立实现，放进本库会重复维护 cgo，并与握手期 Equi-X 混淆。

同一 `quic.Transport` 只有一个非 QUIC 读取点：库创建的探测 Socket 独占最干净；应用已有的 p2p Transport 不能被抢走读取权。

Live 可能数十分钟，必须能取消；纯状态机便于测，Runner 避免每个调用方重写定时器。一次调用一个地址族，与 `pubaddr.md`「要测 IPv4 必须显式走 IPv4」一致。

## 影响 （Consequences）

- Spec 按三个包列导出符号；受托池只定义接口、不提供默认实现。
- `go.mod` 依赖 `github.com/cxio/equix-cgo/puzz`。
- 注入 Transport 的调用方必须把非 QUIC 包交给库，否则 Cone / Live 收不到 SN。
- 禁止迁移后，控制通道地址在一轮探测内视为稳定；换网表现为连接断开（Live 丢弃本轮，见 `keepalive.md`）。
- 粗测/精测可分离的区间导出与注入见 DEC-0006。

## 构想层依据 （Conception References）

- `conception/pubaddr.md`：双栈须显式选路；控制面在已有 QUIC 上。
- `conception/conelevel.md`：技术栈与 ALPN / 首包认证属上层；UDP Blocked 为应用层；综合评估不是本协议职责；TmpN 可外部定制；正式探测须 `ListenUDP`；Passage / Inquire 各拨任意一台；源服务器维护受托连接池并从中抽选；Cone 挑战用 `puzz.Solve` / `puzz.Verify`。
- `conception/keepalive.md`：客户端主导节奏；不要求控制通道与被测映射同公网 IP。
- README：基础库 / 客户端 / 服务器三分。

## 开放问题 （Open Questions）

无。
