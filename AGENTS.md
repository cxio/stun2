# AGENTS.md

## 项目状态

设计阶段的 Go 库，**当前仓库尚无 Go 源码**（除 `go.mod`）。实现前必读：

- `docs/AGENTS.md` — 文档体系权威说明：四层结构 `Conception` + `Decision` > `Proposal` > `Plan` 的权威顺序、各层维护规则、完整的 `DEC-0001~0009` 与 proposal 清单。改任何文档前先读它。
- `docs/conception/` — 三份构想文档（人工主导，最高权威）：`pubaddr.md`（`STUN:Addr`，NAT 公网映射地址获取）、`conelevel.md`（`STUN:Cone`，NAT 类型探测）、`keepalive.md`（`STUN:Live`，映射存活期探测）。
- `docs/decision/DEC-0001-layer-boundary.md` — 协议层与应用层的边界划分：什么必须由本库实现，什么属于 `cxio/p2p` / `stun2p` 等上层项目。判断"某功能该不该写进本库"时先查此文档（其余 `DEC-0002~0009` 主题见 `docs/AGENTS.md` 清单）。
- `docs/proposal/` — 三份可实施技术规格（AI 生成，权威性低于 Conception/Decision）：`wire-spec-v1.md`（控制面帧/WireAddr/Payload）、`sn-spec-v1.md`（SN 二进制布局/HMAC）、`transaction-spec-v1.md`（三原语状态机/冗余时序/去重/NAT 类型语义）。实现时先读对应 proposal，再回溯 decision/conception。
- `MEMORY.md` — 已确认的设计要点（quic-go UDPConn 复用机制成立、keepalive 探测节奏由客户端主导、协议层/应用层区分见 DEC-0001）。

实现新功能时，先以 conception + decision 文档为准；文档与代码冲突时以**已审定的文档**为准（提交历史显示文档经过多轮 AI 评审修订）。若新功能在 conception 中没有明确覆盖，先停止并生成或更新对应的 `docs/decision/` 说明，再继续实现；不得凭直觉补全未定义行为。

- module: `github.com/cxio/stun2`，Go `1.26.2`。
- `docs/plan/` 目前为空（预留目录，由 proposal 转化的阶段化实施计划将放此）。


## 关键架构约束（容易做错）

- 这**不是** RFC 3489 STUN。探测流程基于「STUN 服务节点本身是一个 P2P 网络、节点间可相互协作发包」的前提重新设计，不要照搬传统 STUN 实现（`conelevel.md` 末尾附有 RFC3489 流程图，仅作对照）。
- 通信模式固定为 **QUIC 安全连接 + 底层裸 UDP socket 复用**：QUIC 负责安全传输与控制消息，底层裸 UDP 只承载探测 SN。
- 必须用 `quic-go` 库，且采用 `quic.Transport{Conn: udpConn}` + `Transport.ReadNonQUICPacket()` 模式，由外部传入 `net.UDPConn`（同一 socket 上同时跑 QUIC 与裸 UDP）。库接口测试时无线上实际数据，可用伪造节点元数据替代。
- 服务节点信息（SPKI、ECH 公钥等）来自 [cxio/p2p](https://github.com/cxio/p2p) 项目，不在本库范围内。

### 会话标识 SN — 两套协议规则不同

两套协议 SN 前 48 字节均为 `Rnd16 + HMAC32`，`TmpN` 长度均为 464~1024（隐蔽长度特征）。两者看起来相似，但构造公式和 `Rnd16[0]` 标志位不同，**不要互相套用**：

**Cone（`conelevel.md:§.会话标识`）**——不含地址，客户端无法预知受托服务器，故无法验证 SN：
```
Rnd16[0] = Rnd16[0] & 0x3E | from   // from: 0=NewPort, 1=NewHost
SN = Rnd16 + HMAC_SHA256(Key, Rnd16 + TmpN) + TmpN
```

**Keepalive（`keepalive.md:§.会话标识`）**——含对端 `LocalIP`，双方可互相验证：
```
Rnd16[0] &= 0x3F    // 仅高 2 位清零，无 NewPort/NewHost 标志
SN = Rnd16 + HMAC_SHA256(Key32, Rnd16 + LocalIP + TmpN) + TmpN
```
> `LocalIP` 定长 16 字节，IPv4 走 IPv4-mapped IPv6（`::ffff:a.b.c.d`）。

### NewHost 密钥封装

`NewHost` 消息的 HMAC 密钥是 `SHA256(Key32)`，**不是**原始 `Key32`（防止受托服务器伪装客户端）。源服务器从本机新 IP 发送 `NewHost` 时**同样**使用封装后的密钥（`conelevel.md:§.受托服务器`、`§.客户端（Step.3）`）。

### 冗余发送 & 超时（两套协议不同）

**Cone**（`conelevel.md:§.消息发送；§.客户端超时`）：**NewPort** 发 **5** 次、间隔 `100~400ms` 随机；**NewHost** 发 **3** 次、间隔 `100~300ms; 400~800ms` 区段随机；客户端超时 **5 秒**（一个包都没收到即失败）。NewPort/NewHost 双路并发，统一超时计时。

**Keepalive**（`keepalive.md:§.服务端操作；§.探测循环`）：服务端发 **9** 次，间隔 `100, 200, 400, 800, 1600, 1600, 1600, 1600, 1600ms`，累计约 `9.5s`；客户端超时 **12 秒**。

每次重发都必须**新建 SN**，避免链路中间件合并/丢弃。

### 存活期探测节奏（应用层，非本库实现）

`keepalive.md` 描述了粗测（15s 倍增：15s→30s→60s→…）→ 精测（二分逼近，示例精度 5s）的完整流程，但按 `DEC-0001` 此**节奏调度属应用层**；本库只实现单次 `STUN:Live` transaction（服务端按指数退避冗余发送 SN、客户端验证并用同一 `Key32` 重构 SN 回应、服务端收到有效回应即停止本轮）。不要把粗测/精测调度、跨服务器编排写进本库。起始间隔通常不低于 10s。


## 工作流

- 标准 Go 工具链：`go build ./...`、`go test ./...`、`go vet ./...`。暂无自定义构建/CI/lint 配置，无需寻找 Makefile 或 lint 配置，默认 `go` 命令即权威。
- `go.sum` 当前为空（尚无依赖）；引入 `quic-go` 等依赖后需 `go mod tidy`。


## 约定

- 文档、注释、交互输出用简体中文；程序运行时消息/日志（`fmt`、`errors.New`、`log` 等实参）用英文。
- 标识符、目录/文件名、技术术语沿用英文。


## 实现边界

本项目是 STUN2 协议的接口定义和实现，是一个纯库。协议层（消息/wire format、SN 构造与验证、三个服务原语 `STUN:Addr`/`STUN:Cone`/`STUN:Live` 的单次交互、NAT 类型结果语义）由本库实现；应用层（服务节点发现与选择、探测节奏调度、PoW/Equi-X 反滥用、超时重试与置信度、Exclist 维护策略）由 `cxio/p2p`、`stun2p` 等上层项目负责。归属有疑问时以 `docs/decision/DEC-0001-layer-boundary.md` 为准。