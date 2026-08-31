# DEC-0004 Live 静默路径如何收包

## 背景 （Context）

`STUN:Live` 要求只关闭旧路径上的 `quic.Conn`，从 `Time.0` 起旧 UDP 双方完全静默，并复用旧 Socket 读探测包。quic-go 默认不会这样：Transport 仍可能对误入的 QUIC 形数据包发出 Stateless Reset，从而续活本该闲置的映射，测出的存活期偏长。构想把这一点写成注意，没有选择「保留 Transport 只读」还是「拆掉 Transport 直接读 UDPConn」。

## 决策 （Decision）

1. **旧路径保留 `quic.Transport`，专用于 `ReadNonQUICPacket()` 接收 SN。** 不再在该 Transport 上接受新的 QUIC 连接，也不再从该路径发出任何 QUIC 包（关闭残留窗口内的 `CONNECTION_CLOSE` 除外，见第 3 条）。
2. **必须抑制 Stateless Reset，并从 `Time.0` 起旧路径零发送。** 具体 API 对应留给 Spec，但验收条件是：自 `Time.0` 至本轮结束（含间隔等待），对该 UDP 四元组抓包，除服务端按 `STUN:Live` 请求发出的 SN 和客户端对 SN 的回应外，不应出现其它 UDP 载荷。
3. **首次 `Time.0` 在关闭残留结束之后。** 旧路径 `quic.Conn` 必须干净关闭（向对端发出 `CONNECTION_CLOSE`），好让服务端停发。实现上 quic-go 将已关闭连接的 `CONNECTION_CLOSE` 重传窗口设为 `3*PTO`；等待方式由 Spec 按所选版本落地。首次之后的 `Time.0` 仍按构想规则，不再受关闭残留影响。
4. **服务端对称约束。** 在客户端两次 `STUN:Live` 之间的静默窗口内，服务端不得向被测 `Address` 发送任何包（包括 QUIC 重传、路径探测、Reset）。探测包只在当前 `STUN:Live` 请求验证通过之后，从 Listener 同一 IP:Port 发出。
5. **这是测量正确性的硬不变量**，不是可选优化。做不到静默的实现不得声称符合 `STUN:Live`。

不采用「拆掉 Transport、改用 `UDPConn.ReadFrom`」作为默认路径。若某版本 quic-go 在无连接、且已关闭 Reset 的 Transport 上仍无法停止自发包，再在 Spec 里记录被迫直读 UDPConn 的例外，并仍需满足第 2 条抓包验收。

## 理由 （Rationale）

存活期测的是「静默多久之后入站探测还能否穿过映射」。旧路径上任何自发 UDP（Reset、重传）都会刷新部分 NAT 的计时器，结果偏长且不可复现。`Time.0` 是这段静默的起点：关闭瞬间仍会有 `CONNECTION_CLOSE` 及其短窗口重传，精测量级（如 5 秒）上不可忽略。

不拆栈的默认选择出于三条理由：

1. **关 Conn 之后仍要在同一 Socket 上收 SN。** 保留 Transport 则继续走全库已选定的 `ReadNonQUICPacket()`，没有停读循环再改 `ReadFrom` 的交接，也不在 Live 上另做一套 demux。
2. **拆栈的测量风险在关闭顺序，不在 `Transport.Close()` 本身。** `Transport.Close()` 不发 `CONNECTION_CLOSE`，客户端若未先让服务端停发，服务端会按 PTO 续探，旧映射被续活；只读路径没有所有权转移，也没有「先关 Conn、等残留、再停 Transport」的顺序负担。
3. **服务端 Listener 为多客户端共用，不能为单个被测 Address 拆栈。** 客户端拆掉旧路径 Transport 换不来端到端的结构静默；服务端仍须按第 4 条对 Address 禁发。

## 影响 （Consequences）

- `stun2/client` 在 Step.1 须：干净关闭旧 `quic.Conn` → 等到关闭残留窗口结束 → 记录首次 `Time.0` → 进入「只读裸 UDP」模式；不得丢弃 Transport。
- 构造该 Transport 时不得启用 Stateless Reset（Spec 选定对应字段）；该路径上不再 `Dial` / `Listen`。
- 测试需要能证明：`Time.0` 之后无 `CONNECTION_CLOSE` 重传、无 Reset、无其它额外发包（抓包或可注入的 Transport 替身）。
- 服务端处理 `STUN:Live` 的发送循环不得与该 Listener 上其它 QUIC 连接的重传混淆到被测 Address；被测映射在窗口内不是一条活跃 QUIC 连接。

## 构想层依据 （Conception References）

- `conception/keepalive.md`：Step.1 只关 `quic.Conn`；首次 `Time.0` 在关闭残留发送结束之后；旧链路从 `Time.0` 起双方静默，避免 Stateless Reset；后续 `Time.0` 为对 SN 的最后回包时刻；复用旧 Socket 读；探测包从 Listener 同一 IP:Port 发出；间隔期内旧纯 UDP 完全静默。

## 开放问题 （Open Questions）

无。quic-go 的具体关闭/抑制接口与关闭残留等待方式由 Spec 选定，不在此钉死版本号。
