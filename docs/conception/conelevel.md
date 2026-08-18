# NAT 类型/层级探测：`STUN:Cone`

客户端首先需要连入STUN服务网络，获取多个服务节点的联系信息，其中包含建立安全 QUIC 连接所需的如 `SPKI` 指纹 `Hash256(Cert.SPKI)`、可选的 `ECHConfig` 等。
详见 [cxio/p2p 项目](https://github.com/cxio/p2p)。

然后客户端就可以与这些服务节点建立连接，并请求探测服务。


## 技术栈

- 客户端与服务器间的通信采用 *QUIC 安全连接 & 底层 UDP Socket 复用* 模式，其中 QUIC 用于安全传输，底层裸 UDP 用于 NAT 映射探测。
- Go 语言实现，使用 quic-go 库，参考 `quic.Transport{Conn: udpConn}`, `Transport.ReadNonQUICPacket()` 等用法。

> **特别提示：**
> QUIC 协议要求声明 ALPN，本设计使用标准名称 `h3` 以避免特征。
> 服务器对本协议的辨识采用首包（ClientHello）工作量认证的方式，参考项目 [stun2p](github.com/cxio/stun2p)，[wTLS](github.com/cxio/wtls)。


## 准备

节点首先应当确认自己是否位于 UDP 被封禁的网域：

- 尝试与服务节点建立 QUIC 连接，如果连接成功，则进入下一步，否则继续尝试。
- 如果多次尝试都失败，那大概率 UDP 被封禁（`UDP Blocked`），NAT 探测无意义。结束。

> **提示：**
> 如果已经与服务器建立TCP连接（确定在线），可直接请求其UDP监听地址并尝试连接。
> 因为网络分享的服务器节点信息并不完全可用，所以该选项有更高的优先级。

此为应用层逻辑，由应用层实现。


## 预探测（Step.0）

当确认自己的 UDP 链路可用后，客户端向多个服务节点请求获取自身公网地址（`STUN:Addr`），检查返回结果：

提取返回地址中的端口（`Port`）：

- 如果多个端口都不同，确定为 `Sym-Like`，结束探测。
- 如果多个端口有部分不同，也视为 `Sym-Like`，保守处理，结束探测。
- 如果所有端口都相同，即视为 `非 Sym-Like`，进入下一步……

返回地址与客户端本地数据包出口地址对比（IP:Port 全等比较）：

- 相同（Y）：`Open Internet` | `UDP Firewall`，待进一步确认。
- 不同（N）：待正式探测，进一步判断……


### 实现注意事项

- 客户端需要复用同一个底层 UDPConn 向多个服务器建立 QUIC 并请求 `STUN:Addr` 服务。
- 客户端向多个服务器请求 `STUN:Addr` 的成功返回数量应当不少于**3**个（可配置）。


## 正式探测

客户端向任意一台服务节点请求 NAT 类型探测服务（`STUN:Cone`）。此时为 QUIC 安全连接（**注**：承载通讯）。

如果服务端无法提供探测服务（比如自己连接的受托服务器不足），会返回状态告知。

> **应用提示：**
> 客户端可并发尝试探测以提高结果的可靠性。
> 如果并发，注意彼此的 IP 需要添加到排除清单（`Exclist`，见下文）中。
>
> 注意需用不同的端口创建 UDPConn 监听，否则 `SN` 无法区分。


### 准备

**客户端**通过 `net.ListenUDP` 创建未连接的 Socket，并在此之上创建 QUIC 连接。

同时，客户端通过 QUIC 的 `Transport.ReadNonQUICPacket()` 监听远端的探测回包（*NewPort/NewHost*）。

> **注意：**
> 不能使用 `net.DialUDP`，因为未知 IP 的探测回包（*NewHost*）会被系统丢弃。


### 客户端（Step.1）

客户端在创建的 QUIC 连接上发送 `STUN:Cone` 请求，其中包含如下数据：

- Version: 版本号（初始值 1）。
- Key32:   会话密钥（随机**32**字节），用于构建会话标识（`SN`）。
- Exclist: 排除清单，自上次网络环境变化以来连接过的所有服务器（**注意**：不含当前目标服务器）。

> **解释：**
> `NewHost` 消息需要一个近期未曾与客户端连接过的新IP，因此需要排除清单 `Exclist`。
>
> **提示：**
> 如果客户端提交过大的 Exclist（超过**100**条），服务器可能拒绝为其服务。
> 作为一种良好的实践，客户端应当在初始上线时即请求 NAT 探测服务。

> **实现：**
> 客户端可能需注意 QUIC 中裸 UDP 数据包在队列满后（或业务阻塞）被静默丢弃的问题。


### 会话标识

服务器向客户端发送的探测消息是一个会话标识（`SN`），它有着内在的构造规则。

**SN**的构造规则如下（伪代码）：

```go
// Rnd16: 16字节随机序列。
// Rnd16[0]: 首字节高两位置零，标识非 QUIC 数据包。
// Rnd16[0]: 首字节的低2位用于标记消息源（服务端）：
// - 0：Passage 通路探测
// - 1: NewPort 同机新端口发送
// - 2: NewHost 新主机发送
// source: Passage, NewPort, NewHost
// 位模式：
// - bit7=0 / bit6=0 => QUIC 裸 UDP 标志
// - bit5..bit2 => 随机
// - bit1=0 / bit0=0 => Passage
// - bit1=0 / bit0=1 => NewPort
// - bit1=1 / bit0=0 => NewHost
Rnd16[0] = Rnd16[0] & 0x3C | source

// 服务端构造。
// domainTag: 域标签 "STUN:Cone"
// Key: 会话密钥（Key32）或会话密钥封装（见后）。
// TmpN: 变长随机字节序列，用于隐藏 SN 的长度特征。长度：16 ~ 1024
// 前段固定 16 + 32 = 48 字节。
SN = Rnd16 || HMAC_SHA256(Key, domainTag || Rnd16 || TmpN) || TmpN
```

> **设计：**
> - SN 构造中没有服务端地址，因为对客户端来说，受托服务器未知——无法验证 SN。
> - 服务端发送的探测包数量节制，不考虑客户端对收到的探测包作回应。
> - 服务端发送的探测包无需防重放攻击，因为未知 IP 向客户端发包本就需要（无副作用）。

> **参考：**
> 如果要弱化 SN 特征，TmpN 可能需要特化处理：一个接口，由外部定制该随机序列。


### 服务器（Step.2）

> **规则：**
> 服务端发送的每一个 SN 都是即时构建的，避免链路中间件做优化合并或丢弃。

如果服务器有足够的协助节点连接数，且愿意提供服务：

1. 在 QUIC 连接上回应确认。
2. 在 QUIC 底层 UDP 链路上发送**2**个裸 UDP 包（*通路探测*，端口不变），确认纯 UDP 可以通行。

通路探测的数据包依然为 `SN`，如果客户端收到数据包，即确认网络允许纯 UDP 通讯。否则测试无法进行，客户端可能需要再向不同的服务节点尝试，确认是否为自己网络的问题。

> **设计：**
> 通路探测的数据包「客户端/服务器」超时为**4/6**秒，不可配置。
> 客户端超时起点为收到服务端在 QUIC 上的确认开始，服务端则为发出确认后开始。

如果客户端超时未收到数据包，在 QUIC 上通知服务端并关闭连接。否则向服务器发送通行确认，服务器收到确认后：

- `NewPort`: 用一个新的随机端口向客户端发送消息：数量**4**个，间隔时间 `100ms ~ 400ms` 随机选取。
- `NewHost`: 从本机的另一个新IP或请求另一个服务器（∉ Exclist）向客户端发送消息：数量**3**个，间隔时间 `100ms ~ 500ms` 随机取值。

NewPort 和 NewHost 可以双路并发，两者不冲突。

> **注意：**
> 服务器端使用的新 IP 需要与原连接的IP同簇（同为 IPv4 或 IPv6）。
> 如果源服务器是从本机的一个新IP发送 `NewHost`，Key = `SHA256(Key32)`。

一个源服务器通常需要委托 2~3 个受托服务器发送探测包。标准数量为**3**。源服务器会告知客户端具体的委托数量，这是一种友好的交互。


#### 受托服务器

与客户端直连通讯的服务器称为*源服务器*。如果源服务器请求另一个服务节点协助执行 `NewHost` 委托发包，接受委托的即为*受托服务器*。

如果受托服务器愿意协助发包，为防止恶意委托（DDoS 放大），受托服务器会生成一个随机的挑战种子，回应并要求源服务器完成工作量计算（算法 `Equi-X`）：

```go
// 受托服务器生成挑战种子：
// @DelegateKey 委托服务器密钥（启动后随机生成）
// @ServAddr 源服务器地址（IP:Port）
// @Timepart 当前时间片，2分钟长度
// Timepart = (Now / 120) * 120
challengeSeed = HMAC_SHA256(DelegateKey, ServAddr || Timepart)

// 源服务器计算工作量：
// 将受托目标地址包含进工作量锁定。
// @challengeSeed 受托服务器挑战种子，32字节
// @Address 委托目标地址（接收探测包）
// @KeyHash 会话密钥封装（SHA256(Key32)）
// @nonce 内部生成解的一个随机数，返回用于验证
// @solution 工作量的一个解，16字节（2*8）
solution, nonce, err := equix.Solve(challengeSeed || Address || KeyHash)
```

源服务器完成工作量挑战，然后向受托服务器提供客户端信息及工作量解：

- Version: 版本号（初始值 1）。
- Address: 客户端公网映射地址（`IP:Port`）。
- KeyHash: 客户端的会话密钥封装 `SHA256( Key32 )`。
- Solution: 工作量解，16 字节（8个2字节索引）。
- nonce: 配合工作量解的一个随机数。
- AppInfo: 应用信息，可选。可用于区分支持此协作的不同应用实现。

受托服务器验证工作量解：

```go
// 即时计算挑战种子
// @ServAddr 从连接中提取对端地址
// @Timepart 即时计算时间片（容差内相同）
challengeSeed := HMAC_SHA256(DelegateKey, ServAddr || Timepart)

// 提取源服务器发送的数据
// 验证工作量：受托目标地址和密钥都已锁定
return equix.Verify(challengeSeed || Address || KeyHash, solution, nonce)
```

如果验证通过，受托服务器配合执行 `NewHost` 操作：

- 向目标客户端（`Address`）发送裸 UDP 探测包，数据负载为相同规则构造的 `SN`。
- 探测包数量**3**个，间隔时间 `100ms ~ 500ms` 随机取值。`SN` 各自构造。

> **提示：**
> 源服务器与受托服务器之间通常也是安全连接（QUIC）。
> 实现中 `Equi-X` 工作量计算的成本通常不超过 `50ms`（调整 `effort E`）。

> **实现：**
> 受托服务器应当维护一个 `Address || KeyHash` 的缓存，有效期为时间片长度（2分钟）。
> 发送探测包/验证工作量前，缓存命中的目标地址不再处理（静默忽略）。
>
> 包含 `KeyHash` 是必要的，因为客户端可能并发请求不同的服务器，而它们的委托可能汇聚到同一个受托者。


#### 客户端超时

客户端请求 `STUN:Cone` 服务也有一个超时设置，综合考虑定为**7**秒（可配置）。计时从客户端对*通路探测*的裸 UDP 包确认（QUIC）之后开始。

> **设计：**
> 超时主要权衡：*PoW 计算 + 委托 RTT + 受托方发送窗口 + 抖动* 的开销，附带一点余量。

如果在 7 秒内客户端（`NewPort` | `NewHost`）一个包都没收到，即判定该路径不可达。


### 客户端（Step.3）

如果客户端收到探测包（`SN`）：提取发送源（`NewPort`|`NewHost`），并根据规则验证其有效性。

```go
// 注意 NAT64 环境下服务端 IPv4 的表示法，
// 客户端可能需要从返回的 IPv6 形式中提取出 IPv4 地址，
// 或者都采用 IPv6 形式（进行比较）。
ServIP      // 源服务器IP
ServPort    // 源服务器端口
SourceIP    // 从连接读取远端发送者IP
SourcePort  // 从连接读取远端发送者端口
```

```go
// 是否 NewHost 来源
newHost := SN[0] & 0x3 == 2

// 预防性排除源服务器作假
if newHost && SourceIP == ServIP {
    return false
}
```

```go
// 是否 NewPort 来源
newPort := SN[0] & 0x3 == 1

// 虚假/问题 NewPort
if newPort && (ServPort == SourcePort || SourceIP != ServIP) {
    return false
}
```

```go
// 源服务器可能忽略 Exclist
// NewHost | NewPort 都不允许
// 注意：Exclist 中不能包含源服务器IP本身。
if SourceIP ∈ Exclist {
    return false
}
```

```go
// SN 解构
Rnd16 := SN[:16]
TmpN  := SN[48:]
Hash  := SN[16:48]

// Key32 客户端生成&保留
Key := Key32
if newHost {
    Key = SHA256(Key)
}
return Hash == HMAC_SHA256(Key, domainTag || Rnd16 || TmpN)
```

如果核验通过，则为有效的探测包。

在本设计中，每个受托服务器的发包数都很节制（3个），且历时很短（可能 2~3s），故不设计客户端回应。

> **局限：**
> 本设计基于对源服务器的*基本信任*模型，客户端应当通过*尝试多个不同的服务器请求服务*，并综合权衡。
> 如果 STUN 服务用于区块链环境，代币激励可能有助于节点的诚实行为（详见 [Evidcoin](github.com/cxio/Evidcoin)）。


### 综合判断（Step.4）

客户端根据 `NewPort` 和 `NewHost` 两个连入的情况，综合判断自身 NAT 类型或所在网域。

**NewPort**:
- 收到 => `RC | FullC`。**注**：`FullC` 在 NewHost 段确认&覆盖。
- 超时 => `P-RC | Sym-Like` => `P-RC`。**注**：`Sym-Like` 已在预探测中确认并排除。

**NewHost**:
- 收到 + 预探测.N => `FullC`。
- 收到 + 预探测.Y => `Open Internet`，即 `Public`。
- 超时 + 预探测.Y => `UDP Firewall` 网域。

如果 NewHost 先到，NewPort 的超时等待可以提前结束。也即：如果当前已经可以做出判断，即可终止其它等待。


### 附：判断矩阵

> **注：**
> 不含 `Sym-Like` 条目，其已在预探测阶段完成。

| NewPort 收到 | NewHost 收到 | 与本地地址相同 | 结果 |
|:---:|:---:|:---:|------|
| * | Y | N | Full Cone |
| Y | N | N | RC |
| N | N | N | P-RC |
| * | Y | Y | Open Internet（Public） |
| * | N | Y | UDP Firewall |

**说明：**
- `N` 表示否定（No）。
- `Y` 表示肯定（Yes）。
- `*` 表示无需考虑，N/Y 皆可。


## 探测图示

```graph
                          +------------------+        NewHost Request
                          |      Serv.1      | ---------------------+
                          +------------------+                      |
                            |           /| |                        |
                            |            | |                        |
                            |          1)| |                        V
+--------+                  |   STUN:Cone| |                   +--------+
| Serv.0 |                  |            | |                   | Serv.2 |
+--------+                  |            | |                   +--------+
    |                       |            | | 2)                     |
    |                    0) |            | | NewPort                | 2)
    | 0)             Addr.1 |            | |                        | NewHost
    | Addr.0                |            | |                        |
    V                       V            | V                        V
+-------------------------------------------------------------------------+
|            LocalAddr                 Received?               Received?  |
|                                          3)                      3)     |
|  [Client]                                                               |
+-------------------------------------------------------------------------+


0)
Addr.0 != Addr.1   --> Sym-Like. END.
Addr.0 == Addr.1/
    Addr.1 == LocalAddr (Y)   --> Open Internet | UDP Firewall
    Addr.1 != LocalAddr (N)   --> (Next Step...)

4)
NewPort: Received?
    Yes   --> RC | FullC
    No    --> P-RC
NewHost: Received?
    Yes & 1.N   --> FullC
    Yes & 1.Y   --> Open Internet (Public)
    No  & 1.Y   --> UDP Firewall
```


### 附：传统NAT类型发现流程（RFC3489）

```graph
                        +--------+
                        |  Test  |
                        |   I    |
                        +--------+
                             |
                             |
                             V
                            /\              /\
                         N /  \ Y          /  \ Y             +--------+
          UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
          Blocked         \ ?  /          \Same/              |   II   |
                           \  /            \? /               +--------+
                            \/              \/                    |
                                             | N                  |
                                             |                    V
                                             V                    /\
                                         +--------+  Sym.      N /  \
                                         |  Test  |  UDP    <---/Resp\
                                         |   II   |  Firewall   \ ?  /
                                         +--------+              \  /
                                             |                    \/
                                             V                     |Y
                  /\                         /\                    |
   Symmetric  N  /  \       +--------+   N  /  \                   V
      NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
                \Same/      |   I    |     \ ?  /               Internet
                 \? /       +--------+      \  /
                  \/                         \/
                  |                           |Y
                  |                           |
                  |                           V
                  |                           Full
                  |                           Cone
                  V              /\
              +--------+        /  \ Y
              |  Test  |------>/Resp\---->Restricted
              |   III  |       \ ?  /
              +--------+        \  /
                                 \/
                                  |N
                                  |       Port
                                  +------>Restricted
```

文档：https://datatracker.ietf.org/doc/html/rfc3489#section-10.2
