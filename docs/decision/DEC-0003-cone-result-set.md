# DEC-0003 Cone 对外终态与归属层

## 背景 （Context）

README 列出 8 种终态。判定矩阵在排除 Sym-Like 后给出 5 种；通路失败已命名为 `QUIC Only`；`UDP Blocked` 已划给应用层。构想允许 Passage 与 Inquire 各拨任意一台——QUIC Only 只在 Passage 判定，Inquire 不再测裸 UDP。仍未写明：库一次调用返回哪些枚举、单次通路失败要不要换节点、抽 3 台只收到 2 份挑战怎么办。

## 决策 （Decision）

1. **一次调用的结果。** `stun2/client` 的一次 Cone 探测返回单次路径的结论，枚举为：
   - 预探测：`Sym-Like`
   - 通路失败：`QUIC Only`
   - 正式探测矩阵：`Full Cone`、`RC`、`P-RC`、`Open Internet`（Public）、`UDP Firewall`
2. **不在库内判定。** `UDP Blocked` 由应用在多次 QUIC 拨号失败后自行得出。跨服务器综合评估、换节点重试不在库内。
3. **通路失败。** 单次 Passage 收不到裸 UDP 即返回 `QUIC Only` 并结束该次调用。不在库里做「连续 N 台失败才定 QUIC Only」。
4. **挑战收集。** 源服务器抽选 2～3 台（默认 3）。收集超时前凑齐**至少 2** 份挑战即向客户端返回；不足 2 份则失败（与构想「最少 2 台」一致）。抽 3 是为了提高凑齐下限的概率，不是要求必须等满 3 份。
5. **不可达。** 正式探测中 NewPort / NewHost 在超时前零有效包、校验失败、超时，一律视为该路径不可达，代入判定矩阵。不向调用方暴露这三种内部原因作为 NAT 类型。

Passage 与 Inquire 不必同源，不在此重复决策。

## 理由 （Rationale）

库若包办换节点，就要内置节点表和重试策略，与 DEC-0001 冲突。单次结果加上应用层聚合，符合构想「如实报告、综合评估不是本协议职责」。挑战下限 2 已写在构想里；若坚持抽几份就必须齐，10s 收集超时会把「2 份已够做 NewHost」的成功案例打成失败。

## 影响 （Consequences）

- 公开结果类型不含 `UDP Blocked`，也不含 `Unknown`。探测不确定（例如正式探测前出错）用 error，不用伪类型。
- 应用若要提高置信度，对多个源服务器各调用一次，自己做投票或展示。
- Proposal 的 Cone 服务器：Inquire 在池不足时失败；收集协程在满 2 份后即可返回，不必死等抽选数量。

## 构想层依据 （Conception References）

- `conception/conelevel.md`：前提（UDP Blocked 为应用层）；通路确认与 `QUIC Only`；Inquire 抽 2～3、最少 2 最多 3、池不足返回错误、收集超时；判断矩阵与综合判断；局限（综合评估不是本协议职责）；Passage / Inquire 各拨任意一台。
- README：八种终态的含义。

## 开放问题 （Open Questions）

无。
