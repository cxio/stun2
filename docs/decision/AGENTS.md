# 架构决策（Decision）

定义目标的解决方向、方式，构想没有明确的技术选型、实现路径、必要的关键细节等。完成的是 **Which** 和 **Why this**。由 AI 提出，人类参与互动讨论，最终由人类拍板确定。

不涉及详细的技术规格——评判标准是：如果没有这些决策，技术规格（Spec）部分将无法精确细化。

文档内容基本上遵循如下结构：

- 背景 （Context）
- 决策 （Decision）
- 理由 （Rationale）
- 影响 （Consequences）
- 构想层依据 （Conception References）
- 开放问题 （Open Questions）

> **注：**
> 某些时候可能需要明确*不做什么*，以旁证决策的合理性。


## 文件清单

|    编号    |    文件    |  覆盖主题  |
|------------|------------|------------|
| （待更新） | （待更新） | （待更新） |  （待更新）  |


**维护规则：**

- 新增 Decision 前必须先检查 Conception 部分是否已经明确该规则。
- 若 Conception 已明确，直接引用而不是新增 Decision。
- 若后续 Conception 修订吸收了某个 Decision，应删除该 Decision 或标注已吸收。
- Decision 文件命名为 `DEC-<NNNN>-<short-description>.md`。其中 `<NNNN>` 为序号，如 `0201`（有类别） 或 `0001`（无类别）。
