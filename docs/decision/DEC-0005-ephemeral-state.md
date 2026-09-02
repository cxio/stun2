# DEC-0005 近无状态允许哪些短暂表

## 背景 （Context）

Live 为「极简状态」服务，Cone 受托为「验证即发包」的轻状态协助（构想「单一发包」要求按 Target 去重）。但源服务器要能把 Challenge 对应到受托；受托要抑制同一目标的重复委托；Live 要暂存 `Key32` 才能发 SN 并识别回包；同一地址最小间隔 10s 不可配置。不划清允许的表，Spec 可能无法正确制定规格。

挑战集按 Challenge 索引、TTL 不超过 2 分钟，构想已经写明。Live 探测包发往请求里的 `Address`、不绑控制通道 IP，构想也已经写明。本决策只补「还允许哪些表、键是什么」。

## 决策 （Decision）

服务端允许的短暂存储是闭集，只含下列四项。此外不得为「会话」再建模。

1. **Cone 源：Challenge → 受托地址。** Inquire 收集时写入，对应 `STUN:Cone` 用完即删；最长保留 2 分钟（可配置，默认与挑战有效期相同）。不按 Inquire 连接的客户端地址索引（正式探测已换 `ListenUDP`，映射端口已变）。
2. **Live：当前发送窗的 `Key32`。** 一次 `STUN:Live` 请求验证通过后暂存，用于构造 SN 和验证客户端回包。客户端有效回包或 8 次发完即删。不跨请求复用。
3. **Live：最小间隔表。** 实现构想「同一目标地址 10s 最小间隔」。此处「目标地址」为请求中的目标 **Address**（被测映射），不是控制通道上观测到的 IP:Port。键为 Address，记录上次接受该 Address 的时间；满 10s 可再接受。控制通道因 Arbitrary 池化可以与 Address 不同，按控制通道限速既防不住对同一映射的连打，也会误伤多 Socket 客户端。
4. **Cone 受托：Target 单一发包去重表。** 实现构想「单一发包」：键为 Target（18 字节线格式），值为到期时间；TTL 与受托自己的挑战有效期（Distance，可配置）相同；同一 Target 的 NewHost 在有效期内重复到达时静默丢弃（不发包，响应同正常空成功）。客户端每次正式探测开新端口、Target 各不相同，合法流程不受影响。

受托侧除上述去重表外无其它状态：验证 Challenge 与 Equi-X 后即时发包；SN 不设重放缓存。去重表抑制的是「同一目标的重复委托（重放）」，不是缓存 SN 报文本身。

客户端侧的暂存（`ClientAddr`、`Validation`、`Key32`、`Time.0`）属于探测状态机，不算服务端「无状态」例外，由 `stun2/client` 持有。

## 理由 （Rationale）

四项都是协议能走完的最小记忆。Challenge 键来自客户端带回的 Proofs，与换 Socket 兼容。限速键用被测 Address，与「SN 打向谁」一致，也限制 Validation 持票后对单一映射的发包频率。受托只保留 Target 去重表，是因为构想「单一发包」要求抑制重复委托的重放发包；表随挑战有效期过期，Equi-X 又把证明绑定到 Target，重放被限制在短窗口、固定目标、每目标一次。

## 影响 （Consequences）

- Spec 不得引入「Inquire 会话 ID」「按控制通道 IP 的 Live 会话」等额外表。
- 受托去重表的容量与驱逐策略由 Spec 规定，但不得改键（Target）。
- 限速表容量与驱逐策略（例如按 Address 的 TTL 略大于 10s）由 Spec 规定，但不得改键。
- 源服务器重启后 Challenge 映射丢失，进行中的 Cone 失败，客户端换节点或重走 Inquire。Live 的 `BaseKey` 重启使 Validation 失效，同样回预探测（构想已有）。

## 构想层依据 （Conception References）

- `conception/conelevel.md`：挑战种子到受托地址的映射；TTL 2 分钟；用完即弃；受托协助报文自带 Challenge；「单一发包」要求受托按 Target 去重。
- `conception/keepalive.md`：暂存 Key32 以构造 SN 和验证回包；同一客户端地址 10s 最小间隔；Validation 认证 Address；不要求控制通道与被测映射同公网 IP。

## 开放问题 （Open Questions）

无。
