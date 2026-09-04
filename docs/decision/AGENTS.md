# 架构决策（Decision）

主要为补充 Conception 未直接固定的必要规则、方向取舍/选择，边界划分（可能需要明确不做什么）、架构选型、实现路径等关键决策。通常需要权衡收益/成本/风险/资源等。

不涉及详细的技术规格——评判标准是：如果没有这些决策，技术规格部分（Spec）将无法进行。文档内容基本上遵循如下结构：

- 背景 （Context）
- 决策 （Decision）
- 理由 （Rationale）
- 影响 （Consequences）
- 构想层依据 （Conception References）
- 开放问题 （Open Questions）


## 文件清单

|    编号    |    文件    |  覆盖主题  |
|------------|------------|------------|
| DEC-0001 | `DEC-0001-layer-boundaries.md` | 四包职责与边界：连接所有权、裸 UDP 读取、驱动模型、一次调用范围、`stun2/pow`、Challenge 绑 `SPKIF`、上游服务名识 |
| DEC-0002 | `DEC-0002-control-plane-rpc.md` | 控制面信封、协议全局 Version、每请求一条 Stream、失败可区分（含过期 / 受托拒绝 / 不可用）；通路失败只关连接 |
| DEC-0003 | `DEC-0003-cone-result-set.md` | ConeKind（矩阵五态）与 ConeResult（含提前终态）拆分；QUICOnly 单次即返回；受托池持续抽选；池穷尽且 ≥2 立即返回；术语对照 |
| DEC-0004 | `DEC-0004-live-silent-path.md` | Live 关 Conn 后旧路径只读裸 UDP，抑制 Stateless Reset；首次 Time.0 为 t_CC+1s（窗内有重传则取真实时刻）；服务端禁发从观测 Conn closing 至下次 Live |
| DEC-0005 | `DEC-0005-ephemeral-state.md` | 服务端短暂表闭集五项；发送窗含各服务密钥与 Live Address 注册；常驻非 QUIC 读循环；受托信任边界（拉黑源服务器） |
| DEC-0006 | `DEC-0006-live-bounds.md` | Live 粗测/精测可携带区间：导出给应用、精测只认区间、显式 LiveMode、起始间隔 [10s, 40min]、40 分钟上限为 Unconverged |
| DEC-0007 | `DEC-0007-inquire-rate-limit.md` | Inquire 暂存对端地址；默认 5s、可上调、不得低于 5s；键去端口（IPv4 整地址 / IPv6 /64），`RateLimited` |

Live 控制通道与被测映射的地址关系、取消预环境验证，已写入 `conception/keepalive.md`，不单独立项。

曾用临时裁决单 `DEC-0008-pending-rulings.md` 已吸收完毕，备存于仓库根目录 `working/`，不在本索引内。


**维护规则：**

- 新增 Decision 前必须先检查 Conception 部分是否已经明确该规则。
- 若 Conception 已明确，直接引用而不是新增 Decision。
- 若后续 Conception 修订吸收了某个 Decision，应删除该 Decision 或标注已吸收。
- Decision 文件命名为 `DEC-<NNNN>-<short-description>.md`。其中 `<NNNN>` 为序号，如 `0201`（有类别） 或 `0001`（无类别）。
