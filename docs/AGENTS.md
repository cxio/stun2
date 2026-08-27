# 文档结构

本文档在 `docs` 目录之下，因此子目录和文档文件相对于此目录，不再从项目根目录表达路径。


## 目录设计

项目文档分为四个层级：2个核心层级由用户设计，2个辅助层级由 AI 生成：

| 层级 | 目录 | 作者 | 说明 |
|------|------|------|------|
| Conception（构想层） | `conception/` | 人工 + AI 辅助 | 作者对问题的探索、思考、边界分析以及解决方式等的初始构想。 |
| Decision（决策层） | `decision/` | AI + 人工互助 | 补充完善 Conception 尚未明确的模糊部分或关键的需要细化的决策。 |
| Proposal（提案层） | `proposal/` | AI 生成 + 人工审阅 | 详细技术规格，追溯自 Conception + Decision。 |
| Plan（方案层） | `plan/` | AI 生成 + 人工复核 | 按阶段实施的计划（TDD 任务、包边界、文件清单），追溯自 Proposal。 |

### 权重关系

**权威顺序**：`Conception` + `Decision` > `Proposal` > `Plan`。

如遇冲突以更上层为准，最终以 `Conception` 和 `Decision` 为准。`Decision` 可以是 `Conception` 的细化或模糊 => 明确，但两者不得冲突，否则必须人工介入裁决。

若发现 `Proposal` 或 `Plan` 与 `Conception` 或 `Decision` 不一致，先修改受影响的 `Conception` 或 `Decision` 文档，再重新生成对应的 `Proposal` 和 `Plan` 文件；不要只修改一个文件而不同步其下游内容。

### 排除目录

`plans/`（带 s）用于 AI Agent 工作过程中的临时实施计划，不作为正式文档的一部分；正式方案在 `plan/`。


## 维护总则（Agent）

以上章节和本章节不可修改，这是文档结构的基础设计和关系逻辑。

下面四个章节记录了项目的设计构想、决策、技术提案和实施计划部分，需要根据实际情况更新。


## 设计构想（Conception）

位于 `conception/` 目录下。主要是探索思考，澄清要解决的真实问题、目标场景和用户、预期价值等。是一些初步的构想设计，可能会收集多种可能的方向。

|    功能    |     文件     |  简要说明  |
|------|-------------|-------------|
| NAT 地址探测 | `pubaddr.md` | 向服务器发送 `STUN:Addr` 请求，获得自身公网地址，最简单基础服务。 |
| NAT 类型探测 | `conelevel.md` | 向服务器请求 `STUN:Cone` 服务（含 `STUN:Cone.Passage`），探知自己的 NAT Cone 类型，每台受托服务器最多发送**3**个探测包。 |
| NAT 存活期探测 | `keepalive.md` | 向服务器请求 `STUN:Live` 服务（含 `STUN:Live.Port`），测试自己 NAT 映射的生命期，单轮最多**8**个消息包发送。 |


## 架构决策（Decision）

位于 `decision/` 目录。主要是补充 Conception 未直接固定的必要规则、方向取舍/选择，边界划分（可能需要明确不做什么）、架构选型、实现路径等关键决策。通常需要权衡收益/成本/风险/资源等。

不涉及详细的技术规格，评判标准是：如果没有这些决策，技术规格部分（Proposal）将无法进行。文档内容基本上遵循如下结构：

- 背景 （Context）
- 决策 （Decision）
- 理由 （Rationale）
- 影响 （Consequences）
- 构想层依据 （Conception References）
- 开放问题 （Open Questions）

|    编号    |    文件    |  覆盖主题  |
|------------|------------|------------|
| DEC-0001 | `DEC-0001-layer-boundaries.md` | 三层职责与包边界：连接所有权、裸 UDP 读取、驱动模型、一次调用范围 |
| DEC-0002 | `DEC-0002-control-plane-rpc.md` | 控制面信封、每请求一条 Stream、失败可区分；通路失败只关连接 |
| DEC-0003 | `DEC-0003-cone-result-set.md` | Cone 单次调用终态、QUIC Only 归属、挑战收集下限 2 |
| DEC-0004 | `DEC-0004-live-silent-path.md` | Live 关 Conn 后旧路径只读裸 UDP，抑制 Stateless Reset；首次 Time.0 在关闭残留结束后 |
| DEC-0005 | `DEC-0005-ephemeral-state.md` | 服务端允许的短暂表闭集；Live 10s 限速键为被测 Address |

Live 控制通道与被测映射的地址关系、取消预环境验证，已写入 `conception/keepalive.md`，不单独立项。


维护规则：

- 新增 Decision 前必须先检查 `conception/` 是否已经明确该规则。
- 若 Conception 已明确，直接引用 Conception，不新增 Decision。
- 若后续 Conception 修订吸收了某个 Decision，应删除或标记该 Decision 已被吸收。
- Decision 文件命名为 `DEC-<NNNN>-<short-description>.md`。其中 `<NNNN>` 为序号，可以有类别区分（如 `0201`，第2类第1项），也可没有类别（如 `0001`）。

> **提示：**
> 对于小项目，本层可能会与下面的提案（Proposal）层合并。


## 技术提案（Proposal）

位于 `proposal/` 目录，由 Conception + Decision 生成的可实施技术规格（Spec）。如模块划分、接口与数据设计、字节编码、字段宽度、实现的详细规则等。

文档内容大致遵循如下结构：

- 来源追溯
- 概述
- 规格正文
- 边界与限制
- 待决问题
- 对 Plan 的约束

|    编号    |    文件    |  覆盖主题  |
|------------|------------|------------|
| （待更新） | （待更新） | （待更新） |

维护规则：

- Proposal 的权威性低于 Conception 与 Decision。
- 每篇「来源追溯」必须可回溯到具体 Conception 章节与 `DEC-<NNNN>`。
- 待决项严格限于全局待决集，相关规格须显式标注，不得默认选值固化。


## 实施方案（Plan）

位于 `plan/` 目录，由 Proposal 拆解、转化的有依赖关系的阶段化实施计划（任务序列）。需要估算工作量、分配任务、设定里程碑与验收标准。可能还需要暴露阻塞点，并揭示可并行的部分。

文档内容大致遵循如下结构：

- 来源提案
- 包边界/非目标
- 建议文件
- TDD Task
- 阶段验收/门禁

|    文件    | 覆盖 Proposal | 对应包（层） |
|------------|---------------|--------------|
| （待更新） |  （待更新）   |  （待更新）  |

维护规则：

- 决策引用为 `DEC-<NNNN>` 且主题匹配。
- 待决项对应的 Task 显式标注阻塞/占位。
- 实现任何功能前，应先读对应 `plan/` 文件，再回溯 `proposal/`，如有疑问查 `decision/` 与 `conception/`。
