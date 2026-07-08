# 文档结构

本文档在 `docs` 目录之下，因此子目录和文档文件相对于此目录，不再从项目根目录表达路径。


## 目录设计

项目文档分为四个层级：2个核心层级由用户设计，2个辅助层级由 AI 生成：

| 层级 | 目录 | 作者 | 说明 |
|------|------|------|------|
| Conception（构想层） | `conception/` | 人工编写 | 设计构想，作者对协议、系统和应用边界的原始设计。 |
| Decision（决策层） | `decision/` | AI 生成 + 人工审阅 | 架构决策，仅记录 Conception 尚未明确的补充决策（`DEC-NNNN`）。 |
| Proposal（提案层） | `proposal/` | AI 生成 | 详细技术规格，追溯自 Conception + Decision。 |
| Plan（方案层） | `plan/` | AI 生成 | 按阶段的实施计划（TDD 任务、包边界、文件清单），追溯自 Proposal。 |

### 权重关系

**权威顺序**：`Conception` > `Decision` > `Proposal` > `Plan`。

如遇冲突以更上层为准，最终以 `Conception` 为准。若发现 `Proposal` 或 `Plan` 与 `Conception` 或 `Decision` 不一致，先修改受影响的 `Conception` 或 `Decision` 文档，再重新生成对应的 `Proposal` 和 `Plan` 文件；不要只修改一个文件而不同步其下游内容。

### 排除目录

`plans/`（带 s）用于 AI Agent 工作过程中的临时实施计划，不作为正式文档的一部分；正式方案在 `plan/`。


## 维护总则（Agent）

以上章节和本章节不可修改，这是文档结构的基础设计和关系逻辑。

下面四个章节记录了项目的设计构想、决策、技术提案和实施计划部分，需要根据实际情况更新。


## 设计构想（Conception）

位于 `conception/` 目录下，包含以下内容：

| 功能 | 设计构想文件 |
|------|-------------|
| NAT 地址探测（`STUN:Addr`） | `conelevel.md` |
| NAT 类型探测（`STUN:Cone`） | `conelevel.md` |
| NAT 存活期探测（`STUN:Live`） | `keepalive.md` |


## 架构决策（Decision）

位于 `decision/` 目录。Decision 的作用是补充 Conception 尚未直接固定的规范化细节，例如字节编码、极端边界、字段宽度和实现路径等。

| 编号 | 文件 | 覆盖主题 |
|------|------|---------|
| `DEC-0001` | `decision/DEC-0001-layer-boundary.md` | 协议层与应用层的边界划分 |
| `DEC-0002` | `decision/DEC-0002-transaction-concurrency.md` | `STUN:Cone`/`STUN:Live` 同一 `UDPConn` 上的并发约束、禁止按远端 IP 区分 transaction |
| `DEC-0003` | `decision/DEC-0003-cone-closure-and-cleanup.md` | Cone 关闭握手机制（QUIC 关闭事件）、服务端独立等待超时与资源释放 |
| `DEC-0004` | `decision/DEC-0004-live-localip-binding.md` | Keepalive SN 中 `LocalIP` 取值来源、服务端多归属绑定建议 |
| `DEC-0005` | `decision/DEC-0005-newhost-notice-format.md` | `NewHost` 受托 `Notice` 消息字段格式（含 `AppID`/`AppData` 扩展） |
| `DEC-0006` | `decision/DEC-0006-exclist-upper-bound.md` | `Exclist` 容量上限固定为 256，不做协商 |
| `DEC-0007` | `decision/DEC-0007-control-frame-format.md` | 控制面帧格式（帧头、`MsgType`、错误码结构）、QUIC 传输模型、字节序 |
| `DEC-0008` | `decision/DEC-0008-wire-address-format.md` | 控制消息中 `IP:Port` 的 `WireAddr` 定长编码 |
| `DEC-0009` | `decision/DEC-0009-service-payload-encoding.md` | `STUN:Addr`/`STUN:Cone`/`STUN:Live` 各请求/响应 Payload 字段编码、Live 去重规则 |

维护规则：

- 新增 Decision 前必须先检查 `conception/` 是否已经明确该规则。
- 若 Conception 已明确，直接引用 Conception，不新增 Decision。
- 若后续 Conception 修订吸收了某个 Decision，应删除或标记该 Decision 已被吸收。
- Decision 文件命名为 `DEC-NNNN-<short-description>.md`。


## 技术提案（Proposal）

位于 `proposal/` 目录，由 Conception + Decision 重新生成的可实施技术规格。
每篇含「来源追溯」「规格正文」「边界与限制」「待决问题」「对 Plan 的约束」。

| 编号 | 文件 | 覆盖主题 |
|------|------|------|
| v1 | `proposal/wire-spec-v1.md` | 控制面帧格式、`WireAddr`、三原语 Payload、Notice 消息、错误码 |
| v1 | `proposal/sn-spec-v1.md` | 探测面 SN 二进制布局、位规则、HMAC 构造与验证、`LocalIP` |
| v1 | `proposal/transaction-spec-v1.md` | `STUN:Addr` / `STUN:Cone` / `STUN:Live` 状态机、竞态、冗余发送时序、去重、NAT 类型结果语义 |

维护规则：

- Proposal 的权威性低于 Conception 与 Decision。
- 每篇「来源追溯」必须可回溯到具体 Conception 章节与 `DEC-NNNN`。
- 待决项严格限于全局待决集，相关规格须显式标注，不得默认选值固化。


## 实施方案（Plan）

位于 `plan/` 目录，由 Proposal 转化的阶段化实施计划。与 Proposal 章节、代码包、实施阶段对齐。
每篇含「来源提案」「包边界」「建议文件」「TDD Task」「阶段门禁/验收」。

| 文件 | 覆盖 Proposal | 对应包（层） |
|------|---------------|-------------|
| （待更新） | （待更新） | （待更新） |

维护规则：

- 决策引用为 `DEC-NNNN` 且主题匹配。
- 待决项对应的 Task 显式标注阻塞/占位。
- 实现任何功能前，应先读对应 `plan/` 文件，再回溯 `proposal/`，如有疑问查 `decision/` 与 `conception/`。
