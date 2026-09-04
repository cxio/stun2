# NAT 类型/层级探测：`STUN:Cone`

客户端首先需要连入STUN服务网络，获取多个服务节点的联系信息，其中包含建立安全 QUIC 连接所需的如 `SPKI` 指纹 `SPKIF = Hash256(Cert.SPKI)` 和可选的 `ECHConfig` 等。

然后客户端就可以与这些服务节点建立连接，并请求探测服务。

> **参考：**
> 实际上 STUN2 是 [cxio/p2p](https://github.com/cxio/p2p) 基网上的专用子网，其通过名识（`stun2-service`）来获取同类节点并组网。


## 技术栈

- 客户端与服务器间的通信采用 *QUIC 安全连接 & 底层 UDP Socket 复用* 模式，其中 QUIC 用于安全传输，底层裸 UDP 用于 NAT 映射探测。
- Go 语言实现，使用 quic-go 库，参考 `quic.Transport{Conn: udpConn}`, `Transport.ReadNonQUICPacket()` 等用法。

> **特别提示：**
> QUIC 协议要求声明 ALPN，本设计使用标准名称 `h3` 以避免特征。
> 服务器对本协议的辨识采用首包（ClientHello）工作量认证的方式，参考项目 [stun2p](github.com/cxio/stun2p)，[wTLS](github.com/cxio/wtls)。


## 前提

节点首先应当确认自己是否位于 UDP 被封禁的网域：

- 尝试与服务节点建立 QUIC 连接，如果连接成功，则进入下一步，否则继续尝试。
- 如果多次尝试都失败，那大概率 UDP 被封禁（`UDP Blocked`），NAT 探测无意义。结束。

> **提示：**
> 如果已经与服务器建立TCP连接（确定在线），可直接请求其UDP监听地址并尝试连接。
> 因为网络分享的服务器节点信息并不完全可用，所以该选项有更高的优先级。

此为应用层逻辑，由应用层实现。


## 会话标识（SN）

服务器会在裸 UDP 链路上向客户端发送探测包，探测包的数据是一个简单的会话标识（`SN`），但它有着内在的构造规则：

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
// Key:  会话密钥（Key32）或会话密钥封装（见后）。
// TmpN: 变长随机字节序列，用于隐藏 SN 的长度特征。长度：16 ~ 1024
// 前段固定 16 + 32 = 48 字节。
SN = Rnd16 || HMAC_SHA256(Key, domainTag || Rnd16 || TmpN) || TmpN
```

> **设计：**
> - 服务端发送的探测包数量节制，因此不考虑客户端对收到的探测包作回应。
> - 服务端发送的探测包无需防重放设计，因为未知 IP 向客户端发包本就需要（无副作用）。

> **实现：**
> 为了弱化 SN 特征，TmpN 可能需要特化处理：一个接口，由外部定制该随机序列。


## 预探测

当客户端确认自己的 UDP 链路可用后，从同一个本地端口向多个服务节点请求获取自身公网地址（`STUN:Addr`），进行 `Sym-Like` 排除判断：

提取返回地址中的端口（`Port`）：

- 如果多个端口都不同，确定为 `Sym-Like`，结束探测。
- 如果多个端口有部分不同，也视为 `Sym-Like`，保守处理，结束探测。
- 如果所有端口都相同，即视为 `非 Sym-Like`，进入下一步……

> **注意：**
> 客户端应当在尽可能短的时间内（或并发）向不同的服务节点请求 `STUN:Addr`，
> 以避免 CGNAT 映射重绑定（旧端口被回收）导致的端口不同而误判。


### 实现注意事项

- 客户端需复用同一底层 UDPConn 向多个服务器建立 QUIC 并请求 `STUN:Addr`，以维持同一映射。
- 客户端向多个服务器请求 `STUN:Addr` 的成功返回数量应当不少于**3**个（可配置）。


## 正式探测

**提示**：正式探测与预探测是各自独立的逻辑，与 NAT 映射是否连续没有关系。

**注意**：下面流程中，客户端提供的 `Key32` 每一次都是即时生成的，各自不同。


### 通路确认

客户端向任意一台服务器拨号创建 QUIC 连接，发送 `STUN:Cone.Passage` 请求，其中包含：

- Version: 版本号（初始值 1）。
- Key32:   会话密钥（随机**32**字节），用于构建会话标识 `SN`。

> **实现：**
> 同时，客户端需在 `Transport.ReadNonQUICPacket()` 上启动监听。

服务器收到后，返回确认。然后在 QUIC 底层 UDP 链路上发送**2**个裸 UDP 探测包（端口不变，间隔 `100~300ms` 随机），确认纯 UDP 可以通行。

探测包数据为会话标识 `SN`：

- 如果客户端收到探测包，即确认网络允许纯 UDP 通讯。
- 否则链路为 `QUIC Only`，测试无法继续。客户端关闭 QUIC 连接，结束探测流程。

通路测试的「客户端/服务器」超时为**4/6**秒，不可配置。

客户端的超时起点为收到服务端在 QUIC 上的确认开始，服务端则为发出确认后开始。


### 委托询问

客户端拨号任意一台服务器创建 QUIC 连接，发送 `STUN:Cone.Inquire` 请求，询问对端是否可提供 `STUN:Cone` 探测服务。

- **源服务器**：客户端直接连接询问的服务器，也是直接提供 `STUN:Cone` 服务的服务器。
- **受托服务器**：源服务器请求另一台服务节点协助执行 `NewHost` 委托发包，接受委托的服务器。

源服务器会维护一个连接池，其中包含一定数量受托服务器的节点。

当收到客户端的询问后，源服务器从连接池中随机抽选受托服务器，发送受托协商请求 `STUN:Cone.Challenge`。


#### 受托协商

受托服务器收到协助请求后，若愿意提供协助，即生成工作量挑战种子（`Challenge`）响应；若不愿协助，返回可区分的拒绝，源服务器将该节点计入已尝试并继续抽选。

```go
// 截止时间长度（2分钟，可配置）
// 受托服务器自己的配置，自己知道。
Distance := 120 * time.Second

// 字节序列
// Go/time 中的 Now 为纳秒时间戳，忽略生成重复 Challenge 的可能。
// Encode 变长整数编码（ULEB128 最简编码）
Timestamp := Encode( Now )

// 截止时间戳
Expire := Encode( Now + Distance )

// 受托服务器生成挑战种子：
// DelegateKey 委托服务器密钥（通常启动后随机生成）
// domainTag 域标签：STUN:Cone.Challenge
// SPKIF 源服务器长期身份：当前 QUIC 对端叶证书的 Hash256(Cert.SPKI)，32 字节
Challenge = Timestamp || HMAC_SHA256( DelegateKey, domainTag || SPKIF || Expire )
```

挑战种子没有目标限定，仅绑定源服务器 `SPKIF` 且有效期很短。


#### 受托收集

源服务器联系受托节点不一定每次都成功，可能有的节点暂时不愿受托（这是可能的）。源服务器需要持续尝试并收集同意协助的节点，当收集到**3**台服务器愿意协助后，即可向客户端回应收到的挑战种子（`Challenge`）集。

收集有超时限制，固定为**7**秒（不可配置，因为需要与客户端询问超时配合），若超时时不足**3**台但已凑齐**2**台，也为有效，可向客户端正常回复。否则返回错误，表示无法提供 `STUN:Cone` 服务。

同样，如果连接池数量不足，已遍历完全部节点，则与超时处理逻辑类似——凑齐2台即为有效，且无需等待到超时才返回。

> **实现：**
> 源服务器需要暂存挑战种子与受托服务器地址的映射。


### 创建映射

在超时期限（**11**秒）内，客户端若收到源服务器返回的挑战种子集，即确定服务可用。

然后，客户端用新的端口创建 `net.ListenUDP` 未连接 Socket，并在此之上创建到该源服务器的*新 QUIC 连接*。

> **提示：**
> 客户端可并发尝试不同服务器以请求探测，提高结果的可靠性，
> 但每个并发需要在不同的端口上进行，从根本上隔离数据流，避免混淆会话标识（`SN`）。

**注意**不能使用 `net.DialUDP`，因为受托服务器的探测回包（*NewHost*）是未知 IP，会被系统丢弃。

> **实现：**
> 客户端可能需要注意 QUIC 中裸 UDP 数据包在队列满后（或业务阻塞）被静默丢弃的问题。


#### 获取地址

客户端通过新创建的 QUIC 连接，向服务器发送 `STUN:Addr` 请求，创建并获取当前连接的公网 NAT 映射地址。

服务器返回客户端的公网地址 `IP:Port`。客户端记住该地址，同时与本机*新创建映射*的地址比较：相同（`NewMap.Y`）或不同（`NewMap.N`）。

> **注意：**
> 此处本机地址中的IP非通配的 `0:0:0:0` 或 `[::]`，而是实际网卡的通讯IP。

至此，客户端通过该 QUIC 的 `Transport.ReadNonQUICPacket()` 开始监听远端的探测回包（*NewPort/NewHost*）。


### 请求探测

#### 工作量计算

客户端根据服务器返回的挑战种子，计算工作量（`Equi-X` 算法）：

```go
import "github.com/cxio/equix-cgo/puzz"

// 达标成功率
// 注：固定，不可配置。
const defaultRatio = 0.1

// 阈值门槛（0.1 合法，error 不可能）
threshold, _ := puzz.FromProbability(defaultRatio)

// 工作量运算：
// 将自身公网地址（探测目标）包含进工作量锁定。
// Challenge 挑战种子，32+字节
// Address   客户端公网地址（IP:Port），18 字节线格式
// KeyHash   会话密钥封装（SHA256(Key32)）
// soln      puzz.Solution{Nonce, Solution}
// 起始 nonce 为小素数 13；搜索由 puzz 内部以 0x26f5 步进。
soln, _ := puzz.Solve( SHA256(Challenge || Address || KeyHash), threshold, 13 )
```


#### 发送请求

客户端在新创建的 QUIC 连接上发送 `STUN:Cone` 请求，包含如下数据：

- Version:   版本号（初始值 1）。
- Key32:     会话密钥（随机**32**字节），用于构建会话标识（`SN`）。
- Proofs:    工作量证明集：[Challenge, Solution, Nonce]。

> **提示：**
> 达标率 0.1 时，`puzz` 期望约 6 轮 nonce，整体通常数百毫秒。
> 需要限时或取消时用 `puzz.SolveContext`，不要依赖无上限的 `Solve`。


### 服务响应

#### 验证工作量

源服务器收到客户端请求后，提取数据，验证工作量：

```go
import "github.com/cxio/equix-cgo/puzz"

// 验证工作量：
// ClientAddr 为即时提取，应与上面客户端 STUN:Addr 请求的结果相同。
// 这是一种耦合约束，若不同即验证失败。
//
// ClientAddr 客户端公网地址，从底层连接提取
// KeyHash 会话密钥 Key32 封装：SHA256(Key32)
soln := &puzz.Solution{
    Nonce: Nonce,
    Solution: Solution,
}
return puzz.Verify( SHA256(Challenge || ClientAddr || KeyHash), threshold, soln )
```

> **实现：**
> 源服务器需要暂存挑战种子到受托服务器地址的映射集，算是一种弱状态。
> 挑战种子基于时间戳纳秒精度创建，忽略重复的可能，因此用完即弃。
>
> 挑战种子暂存时间不超过**2**分钟（可配置），过期即可清理（低资源占用）。


#### 完成服务

如果验证通过，源服务器执行如下操作：

- `NewPort`: 用一个新的随机端口（IP不变）向客户端发送探测包（`SN`）：数量**4**个，间隔时间 `100ms ~ 400ms` 随机选取。
- `NewHost`: 向原受托服务器发送完整协助请求（`STUN:Cone.NewHost`）。

NewPort 和 NewHost 可以多路并发，两者并不冲突。

> **提示：**
> 源服务器也可以用本机的新IP代替受托服务器，注意 `Key = SHA256(Key32)`。
> 这是一种可选的灵活性，从外观和有效性上看，两者没有区别。

源服务器向受托服务器发送正式的协助请求，包含如下数据：

- Version:   版本号（初始值 1）。
- KeyHash:   会话密钥封装，即 `SHA256(Key32)`，用于受托服务器构建即时的会话标识 `SN`。
- Target:    探测目标（IP:Port）。
- Challenge: 原挑战种子。由客户端提供的值对应到原受托服务器。
- Solution:  工作量的一个解，16字节。客户端提供。
- Nonce:     配合工作量解的一个随机数。客户端提供。


### 受托协助

#### 验证工作量

受托服务器收到正式的协助请求后，验证发来的数据：

```go
// 验证种子 Challenge

// 截止时间长度（配置值）
Distance := 120 * time.Second

// 当初时间戳
NowOld := Challenge[0:len(Challenge)-32]
Expire := Decode(NowOld) + Distance

// 种子有效性
if Now > Expire {
    return false // 已过期
}

// 种子合法性
// domainTag: STUN:Cone.Challenge
// SPKIF: 当前 QUIC 对端叶证书的 Hash256(Cert.SPKI)，须与签发时同一源服务器
Hash := HMAC_SHA256( DelegateKey, domainTag || SPKIF || Encode(Expire) )

// 若返回 false,
// 可能是 Challenge 前置的时间戳被修改
return Hash == Challenge[len(NowOld):]
```

```go
import "github.com/cxio/equix-cgo/puzz"

// 验证工作量
// Target 应当与前面 ClientAddr 和 Address 是同一个值。
soln := &puzz.Solution{
    Nonce: Nonce,
    Solution: Solution,
}
return puzz.Verify( SHA256(Challenge || Target || KeyHash), threshold, soln )
```


#### 协助发包

如果验证通过，受托服务器配合执行 `NewHost` 操作：

- 向目标客户端（`Target`）发送裸 UDP 探测包，数据负载为相同规则即时构造的 `SN`。
- 探测包数量**3**个，间隔时间 `100ms ~ 500ms` 随机取值。

为避免源服务器的重复委托带来的重放问题，受托服务器需要暂存目标地址（`Target`），不重复接受委托发包。暂存期时长与挑战种子有效期相同即可。

> **提示：**
> 客户端的每一次正式探测请求 `STUN:Cone` 都是开新端口，无「相同映射不同委托」的问题。


### 客户端收包

如果客户端收到探测包（`SN`）：提取发送源（`NewPort`|`NewHost`），并根据规则验证其有效性。

```go
// 基础数据
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
// SN 解构
Rnd16 := SN[:16]
TmpN  := SN[48:]
Hash  := SN[16:48]

// Key32 客户端生成&保留
Key := Key32
if newHost {
    Key = SHA256(Key)
}
// 验证结果
return Hash == HMAC_SHA256(Key, domainTag || Rnd16 || TmpN)
```

如果核验通过，则为有效的探测包。

> **局限：**
> 本设计基于对源服务器的*基本信任*模型，客户端应当尝试*向多个不同的服务器请求服务*，
> 不同的服务器返回的结果可能不同，客户端如实报告即可。综合评估不是本协议的职责。
>
> 另：区块链的代币激励可能有助于节点诚实履约（详见 [Evidcoin](github.com/cxio/Evidcoin)）。


#### 客户端超时

客户端等待 `STUN:Cone` 的探测回包的超时为**6**秒（可配置），计时从客户端发送完最后一个 `STUN:Cone` 请求开始。

> 超时主要权衡：*两级 PoW 验证 + 委托 RTT + 受托方发送窗口 + 抖动* 的开销，附带一点余量。

如果在超时前客户端（`NewPort` | `NewHost`）一个包都没收到，即判定该路径不可达。


### 综合判断

客户端根据 `NewPort` 和 `NewHost` 两个连入的情况，综合判断自身 NAT 类型或所在网域。

**NewPort**:
- 收到 => `RC | FullC`。**注**：`FullC` 在 NewHost 段确认&覆盖。
- 超时 => `P-RC | Sym-Like` => `P-RC`。**注**：`Sym-Like` 已在预探测中确认并排除。

**NewHost**:
- 收到 + NewMap.N => `FullC`。
- 收到 + NewMap.Y => `Open Internet`，即 `Public`。
- 超时 + NewMap.Y => `UDP Firewall` 网域。
- 超时 + NewMap.N => 不单独定论，交给 NewPort 判断 `RC` / `P-RC`（见矩阵）。

如果 NewHost 先到，NewPort 的超时等待可以提前结束。也即：如果当前已经可以做出判断，即可终止其它等待。


### 附：判断矩阵

> **注：**
> 不含 `Sym-Like` 条目，其已在预探测阶段完成。

| NewPort 收到 | NewHost 收到 | 与本机地址对比 | 结果 |
|:---:|:---:|:---:|------|
| * | Y | N | Full Cone |
| Y | N | N | RC |
| N | N | N | P-RC |
| * | Y | Y | Open Internet（Public） |
| * | N | Y | UDP Firewall |

**说明：**
- `N` 表示否定/不同（No）。
- `Y` 表示肯定/相同（Yes）。
- `*` 表示无需考虑，N/Y 皆可。


## 探测图示

预探测与正式探测使用不同的本地 Socket，图中分开画出。预探测须向**不少于 3 台** Addr 服务器取映射（可配置）；图示只画 3 台。

```graph
预探测（同一本地端口，不少于 3 台 Addr 服务器）

    Serv.A --Addr.A--> +--------+ <--Addr.B-- Serv.B
                       | Client |
    Serv.C --Addr.C--> +--------+

Addr.A / Addr.B / Addr.C 端口:
    不全相同 --> Sym-Like. END.
    全部相同 --> 通路确认 --> 正式探测
```

```graph
正式探测（新 ListenUDP；与预探测映射无关）

            +------------------------+            NewHost Request
            |     源服务器 Serv.1    |--------------------------+
            +------------------------+                          |
               |               /| |                             |
               |                | |                             |
               |              1)| |                             V
               |       STUN:Cone| |                       +----------+
               |                | |                       |  Serv.2  |
               |                | |                       |  (受托)  |
               |                | | 2)                    +----------+
            0) |                | | NewPort                     | 2)
        GetAddr|                | |                             | NewHost
               |                | |                             |
               V                | V                             V
+-----------------------------------------------------------------------+
|         LocalAddr          Received?                      Received?   |
|                                3)                             3)      |
|  [Client]  新 ListenUDP                                               |
+-----------------------------------------------------------------------+

0) GetAddr：
    与本机新映射比较 --> NewMap.Y / NewMap.N

通路（可另拨任意一台，不必是 Serv.1）：
    QUIC => ok
    Naked UDP => timeout --> QUIC-Only. END.

2)
NewPort: Received?
    Yes   --> RC | FullC
    No    --> P-RC
NewHost: Received?
    Yes & NewMap.N  --> FullC
    Yes & NewMap.Y  --> Open Internet (Public)
    No  & NewMap.Y  --> UDP Firewall
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
