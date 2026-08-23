# AGENTS.md

## 项目定位

STUN2：NAT 映射类型与存活期探测库（Go 模块 `github.com/cxio/stun2`）。基于 P2P 协作服务网络的新式 STUN 探测流程，非 RFC 3489 传统实现。

**全新构建**：忽略 git 历史（历史中的旧实现与旧文档已删除，不具任何权威性）。当前权威设计仅为 `docs/conception/` 下三篇构想文档：

- `pubaddr.md` — `STUN:Addr` 公网地址获取（最基础服务，另被 Cone 预探测与 Live 预环境验证复用）
- `conelevel.md` — `STUN:Cone` NAT 类型探测，含 `STUN:Cone.Passage`, `STUN:Cone.Inquire`, `STUN:Cone.Challenge`, `STUN:Cone.NewHost`。
- `keepalive.md` — `STUN:Live.Port/STUN:Live` NAT 映射存活期探测

README 将库划分为三部分：基础库（公共结构与格式规范）、客户端、服务器（各自的行为规范与建议）；后续包边界划分以此为基础。

项目目前处于设计阶段：`docs/decision/`、`docs/proposal/`、`docs/plan/` 尚为空（git 不跟踪空目录，克隆后需自建），代码未开始编写。

## 文档体系（必读）

`docs/AGENTS.md` 定义四层文档结构、权威顺序（`Conception` + `Decision` > `Proposal` > `Plan`）与维护规则，其中「目录设计」与「维护总则」两章节明确不可修改。日常工作的关键规则：

- 实现任何功能前，先读对应 `plan/` 文件，再回溯 `proposal/`，有疑问查 `decision/` 与 `conception/`。
- 发现 Proposal/Plan 与上层文档不一致时，先修改 Conception/Decision，再重新生成下游文件；不得只改一处而不同步。
- 新增 `decision/`、`proposal/`、`plan/` 文件时，须同步更新 `docs/AGENTS.md` 对应章节的索引表（现为「待更新」占位）。
- `plans/`（带 s）是 Agent 临时实施计划目录，不属于正式文档；正式方案在 `plan/`。
- Decision 文件命名：`DEC-NNNN-<short-description>.md`；新增前须先确认 Conception 未曾明确该规则。

## 关键技术约束

以下为三篇构想文档中分散但容易违反的跨切面不变量：

- 核心依赖 quic-go 的「同一 UDPConn 复用 QUIC + 裸 UDP」机制（`quic.Transport{Conn: udpConn}`、`Transport.ReadNonQUICPacket()`），可行性已评审确认（见 `MEMORY.md`）。
- 客户端 `STUN:Cone` 正式探测（创建映射）阶段的新 Socket 必须用 `net.ListenUDP`（未连接 Socket），不可用 `net.DialUDP`——未知 IP 的探测回包（NewHost）会被系统丢弃。`STUN:Addr` 与 `STUN:Live` 无此限制（回包源 IP 已知，拨号创建的连接即可）。
- QUIC ALPN 统一使用标准名 `h3`（避免协议特征）；服务器对协议的辨识采用首包（ClientHello）工作量认证（Equi-X）。这属于上层应用行为，不在本库实现范围。
- 地址统一为 IPv6 格式，IPv4 采用 IPv4-mapped 编码（`::ffff:IPv4`）。
- 裸 UDP 探测包为会话标识 SN：`Rnd16[0]` 高两位置零以标识非 QUIC 包；Cone 中低 2 位另用于标记消息源（`Rnd16[0] & 0x3C | source`：0=Passage、1=NewPort、2=NewHost），Live 则保留低 6 位（`& 0x3F`）。每个 SN 均即时构建、互不相同。
- 协议默认常量（除注明外均可配置）：Cone 每台受托服务器发包上限 3、客户端探测回包超时 6s；Live 单轮发包上限 8、客户端超时 10s、Validation 有效期上限 45 分钟。粗测起始间隔无固定默认值，由用户按网络环境配置，但硬性下限为 10s（须大于服务端冗余发包总长 7.9s 加余量）。
- 例外：Cone 通路探测超时 4/6s（客户端/服务端）不可配置，是少数硬编码常量之一。

## 命令

尚无构建脚本、CI 与 lint 配置。常规验证：

```
go vet ./...
go test ./...
```

依赖尚未引入（go.sum 为空），需要 quic-go 等依赖时正常 `go get` 即可。

## 约定

- 文档与代码注释使用中文；标识符、日志、错误消息沿用英文。
- 协议域标签沿用文档中的既有命名（`STUN:Addr`、`STUN:Cone`、`STUN:Cone.Passage/Inquire/Challenge/NewHost`、`STUN:Live.Port`、`STUN:Live`、`Server@STUN:Live`、`Client@STUN:Live`），不得自创变体。
