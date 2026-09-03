# DEC-0007 Inquire 请求级限速

## 背景 （Context）

`STUN:Cone.Inquire` 载荷为空。源服务器在 7s 收集窗内持续抽选受托、签发 Challenge，并写入 Challenge 表（DEC-0005 第 1 项，容量建议 4096，满则 `InsufficientTrustees`）。握手期 Equi-X 属上层（DEC-0001），不覆盖握手后的 Stream。Live 已有按被测 Address 的 10s 限速；Inquire 没有对等约束。

DEC-0005 禁止「Inquire 会话 ID」：正式探测已换 `ListenUDP`，不能把后续 `STUN:Cone` 绑回 Inquire 连接，Challenge 表也不得按客户端地址索引。该禁令不回答「谁在触发收集窗」。闭集可以另存一份与 Challenge 表无关的客户端地址，只用来约束 Inquire 速率。

没有这份决策，Spec 无法写出该暂存的键、有效期与拒绝码。

## 决策 （Decision）

1. **只限 Inquire。** 源服务器在启动收集窗之前查客户端地址暂存。键仍在有效期内则 `RateLimited`：不 `Pick`、不向受托发 `STUN:Cone.Challenge`、不写 Challenge 表。`STUN:Cone.Passage` / `STUN:Cone` / `STUN:Addr` 不加对等限速。
2. **暂存 Inquire 对端地址，不是会话。** 键从控制通道 `RemoteAddr` 去掉端口：IPv4 与 IPv4-mapped 取 32 位地址；IPv6 取 `/64`。值为到期时间。不索引 Challenge，不把后续 `STUN:Cone` 关联到这条 Inquire 连接。同一键上检查与写入必须串行，同时至多接受一个。
3. **有效期 30s，不可配置。** 进入收集窗时写入（或刷新）到期时间 `now+30s`，即使该次随后 `InsufficientTrustees`。项在有效期内即拒绝；过期删除。30s 大于 7s 收集窗，同一键不会重叠收集。
4. **与表满分工。** 限速用 `RateLimited`；Challenge 表满仍用 `InsufficientTrustees`。二者不可混用。
5. **闭集增补。** 该暂存列为 DEC-0005 第 5 项。不因此放开 Inquire 会话或按控制通道 IP 的 Live 会话。

握手期工作量认证仍属上层，本决策不把它下放到本库。

## 理由 （Rationale）

空 Inquire 的成本在源服务器的收集窗和共享 Challenge 表。表满拒绝会伤及其他客户端。按 IP:Port 暂存无效：换本地端口即新键。Challenge 表继续按 Challenge 索引，是为了换 Socket 之后仍能把 Proof 对回受托；速率表只记「谁刚发过 Inquire」，两套键不冲突。

IPv6 取 `/64`：同一订阅者块内换接口 ID 不得换桶。IPv4 不按 `/24` 聚合，避免误伤无关主机。30s 占用窗比 Live 的 10s 更疏：Cone 非高频，单源在 Challenge 2 分钟 TTL 内最多约 4 次收集，灌表效率低于 10s 间隔。复用已有 `RateLimited`。

客户端等待挑战集 11s 后立刻重试会撞限速，须等到该项过期。合法路径一次探测只 Inquire 一次；超时重试由应用间隔 30s，或换源服务器。

分布式多前缀灌表不在本库消除；应用仍可在接入层加更严的连接限制。

## 影响 （Consequences）

- Spec 规定键导出、30s 有效期、串行接受、容量与驱逐；常量列入 SPEC-0001。
- 同一公网 IPv4 或同一 IPv6 `/64` 上，有效期内第二次 Inquire 被拒。构想允许的「并发换服务器」不受影响（每台源服务器各有各表）。
- CGNAT 共享 IPv4 时，该公网地址共享同一个 30s 占用窗。
- Challenge 表满与限速对客户端可区分（`InsufficientTrustees` vs `RateLimited`）。

## 构想层依据 （Conception References）

- `conception/conelevel.md`：Inquire 载荷无证明；收集窗 7s 持续抽选；客户端等待 11s；正式探测换 `ListenUDP`；可并发尝试不同服务器。
- `DEC-0001`：握手期 Equi-X 属上层；本库不实现接入认证。
- `DEC-0002`：失败可区分，含限速。
- `DEC-0005`：短暂表闭集；Challenge 表不按客户端地址索引；禁止 Inquire 会话 ID。

## 开放问题 （Open Questions）

无。
