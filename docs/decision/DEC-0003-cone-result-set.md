# DEC-0003 Cone 对外终态与归属层

## 背景 （Context）

README 列出 8 种终态。判定矩阵在排除 Sym-Like 后给出 5 种；通路失败已命名为 `QUIC Only`；`UDP Blocked` 已划给应用层。构想允许 Passage 与 Inquire 各拨任意一台——QUIC Only 只在 Passage 判定。收集规则构想已钉死（满 3 立即返回；7s 超时且已有 2 份亦有效）。仍未写明：库一次调用返回哪些枚举、单次通路失败要不要换节点、池抽选接口如何支撑「持续尝试」而不是一次固定批次。

## 决策 （Decision）

1. **一次调用的结果，类型拆分。** `stun2/client` 的一次 Cone 探测返回单次路径的 `ConeResult`，可在任一阶段提前终止：
   - 预探测提前终态：`SymLike`
   - 通路失败提前终态：`QUICOnly`
   - 正式探测矩阵（`ConeKind`，根包 `ClassifyCone` 的值域）：`FullCone`、`RC`、`PRC`、`OpenInternet`、`UDPFirewall`

   `ConeKind` **不含** `SymLike` / `QUICOnly`。这两态由状态机直接得出，不进入判定矩阵。不确定（拨号失败、受托不足、Equi-X 无解、控制面 Status≠0、ctx 取消等）用 `error`，不用伪类型。
2. **不在库内判定。** `UDP Blocked` 由应用在多次 QUIC 拨号失败后自行得出。跨服务器综合评估、换节点重试不在库内。
3. **通路失败。** 单次 Passage 收不到裸 UDP 即返回 `QUICOnly` 并结束该次调用。不在库里做「连续 N 台失败才定 QUIC Only」。
4. **挑战收集（跟构想，不另定数量/超时）。** 源服务器在收集窗内持续从池中抽选尚未尝试的受托，发送 `STUN:Cone.Challenge`：凑齐 **3** 份即向客户端返回；收集超时固定 **7s**（不可配置），**仅在超时时刻**已有 **2** 份亦成功，否则失败。2 是超时下限，不是提前返回条件。池接口须支持在该窗内多次抽选；不得写成一次 `Pick(N∈[2,3])` 之后只等这一批、满 2 就返回。活节点不足 3 时仍继续，超时有 2 即成功。客户端等待挑战集固定 **11s**（不可配置）。
5. **不可达。** 正式探测中 NewPort / NewHost 在超时前零有效包、校验失败、超时，一律视为该路径不可达，代入判定矩阵。不向调用方暴露这三种内部原因作为 NAT 类型。

Passage 与 Inquire 不必同源，不在此重复决策。

## 理由 （Rationale）

库若包办换节点，就要内置节点表和重试策略，与 DEC-0001 冲突。单次结果加上应用层聚合，符合构想「如实报告、综合评估不是本协议职责」。矩阵五态与前置两态分开，避免 `ClassifyCone` 值域被塞进提前终止，也避免用 `error` 表示 `QUIC Only`。收集的完成条件与超时已由构想写明；Decision 只约束池接口不得把「满 2 即返回」或「一次固定批次」当成收集策略，否则 2 节点部署会提前结束、3 节点部署也会在凑齐第 3 份之前返回。

## 影响 （Consequences）

- 根包导出 `ConeKind`（五态）与 `ClassifyCone`；`stun2/client` 的 `RunCone` 返回 `ConeResult`（前置两态 + 五态），不得把 `ConeKind` 直接当作一次调用的返回类型。
- 公开结果类型不含 `UDP Blocked`，也不含 `Unknown`。探测不确定用 error，不用伪类型。
- 应用若要提高置信度，对多个源服务器各调用一次，自己做投票或展示。
- Spec 的受托池：`Pick` 为收集循环的抽选材料（可多次、可不足 3、排除已尝试）；Inquire 收集协程满 3 立即返回，7s 超时且 ≥2 才按下限成功；客户端 Inquire 等待 11s。

## 构想层依据 （Conception References）

- `conception/conelevel.md`：前提（UDP Blocked 为应用层）；通路确认与 `QUIC Only`；受托收集持续尝试、满 3 立即返回、收集超时 7s 不可配置、超时有 2 亦有效；客户端等待挑战集 11s；判断矩阵与综合判断；局限（综合评估不是本协议职责）；Passage / Inquire 各拨任意一台。
- README：八种终态的含义。

## 开放问题 （Open Questions）

无。
