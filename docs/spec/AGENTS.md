# 技术规格（Spec）

由 Conception + Decision 生成的技术规格（Spec）。如模块划分、接口与数据设计、字节编码、字段宽度、实现的规则等。请在必要的精简和足够的细粒度之间保持良好权衡。

文档内容大致遵循如下结构：

- 来源追溯
- 概述
- 规格正文
- 边界与限制
- 待决问题
- 对 Plan 的约束


## 文件清单

|    编号    |    文件    |  覆盖主题  |
|------------|------------|------------|
| SPEC-0001 | `SPEC-0001-wire-and-core.md` | 控制信封、全局 Version、错误码（含 Declined / Unavailable / Expired）、地址与 SPKIF、SN、HMAC/时间窗、Equi-X 种子与 `stun2/pow`、协议常量、`LiveBounds` / `CanFine` / `LiveMode`、`stun2` 导出 |
| SPEC-0002 | `SPEC-0002-stun-addr.md` | `STUN:Addr` 载荷与两端行为 |
| SPEC-0003 | `SPEC-0003-stun-cone.md` | Passage / Inquire / Challenge / Cone / NewHost、判定矩阵、`ConeResult`、Inquire 收集（满 3 / 池穷尽满 2 立即返回 / 7s / 11s）、Inquire 限速、受托池接口、`NewHostRequest` |
| SPEC-0004 | `SPEC-0004-stun-live.md` | Live.Port / Live、静默路径与首次 Time.0、粗测/精测与四种结束、`LiveMode`、`LiveBounds` 导出/注入、常驻非 QUIC 读循环与 Address 发送窗 |


**维护规则：**

- Spec 服从于 Conception 与 Decision。
- 每篇「来源追溯」必须可回溯到具体 Conception 章节与 `DEC-<NNNN>`。
- 待决项严格限于全局待决集，相关规格须显式标注，不得默认选值固化。
