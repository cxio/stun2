# SPEC-0001 控制信封、公共编解码与 `stun2` 根包

## 来源追溯

- `conception/pubaddr.md`：地址为 IPv6 形式，IPv4 用 IPv4-mapped；Version 初始值 1；不符则错误。
- `conception/conelevel.md`：SN 构造、Cone 首字节来源位、TmpN、Challenge HMAC、Equi-X 种子为 `SHA256(Challenge || Address || KeyHash)`，调用 `puzz.Solve` / `puzz.Verify`；起始 nonce 为 13。
- `conception/keepalive.md`：Live SN 首字节、双向 domainTag、Validation HMAC、时间戳 ULEB128。
- `DEC-0001`：`stun2` 为纯函数与编解码，无网络 IO；TmpN 默认可注入；Equi-X 只组装输入并调用 `github.com/cxio/equix-cgo/puzz`。
- `DEC-0002`：信封为方法名 + Version + 载荷；每请求一条 Stream；失败可区分；数值错误码与字节布局由本 Spec 钉死。
- `DEC-0003`：判定矩阵五种终态的纯函数落在根包；`UDP Blocked` / `Unknown` 不出现。
- Equi-X 接口以 [cxio/equix-cgo/puzz](https://github.com/cxio/equix-cgo/tree/main/puzz) 为准，模块路径 `github.com/cxio/equix-cgo/puzz`。


## 概述

本 Spec 规定所有控制面共用的线格式、错误码、地址与 SN 公共构造、Challenge / Validation 的 HMAC 与时间窗，以及根包 `stun2` 的导出符号。方法各自的 Payload 与状态机见 SPEC-0002～0004。


## 规格正文

### 1. 传输约定

- 每个请求在 QUIC 连接上新开一条双向 Stream；响应走同一条；写完请求后关闭写端；对端 FIN 即消息边界。不在一条长流上排队，不使用 DATAGRAM。
- 不另加外层总长度。多字节整数（除 ULEB128 与 Equi-X 解的 16 字节编码外）一律**大端**。
- 当前所有方法的 Version 均为 `1`。各方法的 Version 独立演进；不支持则拒绝，不降级。
- 探测用连接禁止 path migration：库创建的连接不得调用 `AddPath`。
- ALPN `h3`、TLS / SPKI、ClientHello 工作量认证由应用提供，不在本库。

### 2. 控制信封

**请求**（读到 FIN）：

| 偏移 | 字段 | 宽度 | 规则 |
|------|------|------|------|
| 0 | Version | u8 | 当前 1 |
| 1 | MethodLen | u8 | 1–64；0 或 >64 为非法载荷 |
| 2 | Method | MethodLen | ASCII，即协议域标签本身 |
| 2+MethodLen | Payload | 直至 FIN | 上限 8192 字节 |

方法名必须是下列之一，不得使用别名：

`STUN:Addr`、`STUN:Cone.Passage`、`STUN:Cone.Inquire`、`STUN:Cone`、`STUN:Cone.Challenge`、`STUN:Cone.NewHost`、`STUN:Live.Port`、`STUN:Live`。

**响应**（同一条 Stream）：

| 偏移 | 字段 | 宽度 | 规则 |
|------|------|------|------|
| 0 | Version | u8 | 回显请求 Version |
| 1 | Status | u8 | 0 = 成功 |
| 2 | Payload | 直至 FIN | 成功时为方法载荷；失败时为空 |

解析顺序：先读 Version，不支持则回 `UnsupportedVersion` 并停读；再读方法名，未知则 `UnknownMethod`；再读 Payload，超过 8192 或 Method 段截断则 `InvalidPayload`。方法内字段非法也归 `InvalidPayload`。密码学或证明失败才用 `VerifyFailed`。

连 Version 都读不到（空流）：关闭 Stream，不发应用层响应。

### 3. 错误码（Status）

| 值 | 导出名 | 含义 |
|----|--------|------|
| 0 | `StatusOK` | 成功 |
| 1 | `ErrUnknownMethod` | 未知方法 |
| 2 | `ErrUnsupportedVersion` | 不支持的 Version |
| 3 | `ErrVerifyFailed` | Equi-X / Validation / Challenge 校验失败 |
| 4 | `ErrInsufficientTrustees` | 受托不足或收集不够下限 |
| 5 | `ErrRateLimited` | 限速 |
| 6 | `ErrInvalidPayload` | 截断、超长或字段非法 |

根包提供与上表对应的 sentinel error（`errors.Is` 可判定）。通路失败（`QUIC Only`）不走 Status：客户端只关 QUIC 连接。

### 4. 公共字段约定

- 定长按宽度紧密排列。
- 变长字节：`u16` 长度 + 内容。
- 时间戳：ULEB128 **最简编码**（禁止多余前导零）。编码对象是 `uint64`。
- 列表：`u8` 个数 + 元素。Cone Proofs 个数必须是 2 或 3。

### 5. 地址

线格式固定 18 字节：`IP[16] || Port[2]`，Port 为大端 `uint16`。

- IPv4 必须写成 IPv4-mapped（`::ffff:x.x.x.x`），禁止 4 字节 IP。
- 规范化：`ip.To4() != nil` 则存 mapped 16 字节，否则存原生 IPv6 16 字节。
- 一次调用一个地址族；根包不合并 IPv4 / IPv6。

导出类型 `Addr` 与函数：`Normalize`、`Encode` / `Decode`（18 字节）、`Equal`、`EqualIP`、`EqualPort`。

下列材料一律使用这 18 字节，不得另编码：`STUN:Addr` 响应、Challenge HMAC 中的 `ServAddr`、Validation 中的 `ClientAddr`、`STUN:Live` 的 `Address`、Equi-X 种子中的 `Address`。

### 6. SN

```
SN = Rnd16 || HMAC_SHA256(Key, domainTag || Rnd16 || TmpN) || TmpN
```

长度 64–1072。每个 SN 当场构建，禁止复用 `Rnd16` 或整包。`Rnd16` 来自 CSPRNG，再盖首字节戳。

**首字节**（构造时写入；校验时 bit7、bit6 必须为 0）：

| 用途 | 规则 |
|------|------|
| Cone | `Rnd16[0] = Rnd16[0] & 0x3C \| source`；source：0=Passage，1=NewPort，2=NewHost |
| Live | `Rnd16[0] &= 0x3F` |

`domainTag` 与 `Key` 由调用方传入。根包提供盖戳、`BuildSN`、`VerifySN`，不绑定某一服务。

Cone 的 NewHost 使用 `Key = SHA256(Key32)`，其余 Cone 探测使用 `Key32`。Live 使用 `Key32`，方向 tag 为 `Server@STUN:Live` 或 `Client@STUN:Live`。

**TmpN：** 长度 16–1024。默认用 `crypto/rand` 先抽长度再填字节。可注入：

```go
type TmpNFunc func() ([]byte, error)
```

注入函数返回越界或错误则构造失败，不静默裁剪。Cone 探测包不做客户端回 SN，也不做 SN 重放缓存；受托侧按 Target 的「单一发包」去重表是另一机制（见 SPEC-0003 §4.6，DEC-0005 闭集第 4 项）。

### 7. Challenge 与 Validation

两类时钟不得混用。

**Cone Challenge**（Unix **纳秒**）：

```
ts     = uint64(now.UnixNano())
expire = ts + uint64(ttl)          // ttl 为 time.Duration，纳秒数
Challenge = ULEB128(ts) || HMAC_SHA256(DelegateKey, ServAddr18 || ULEB128(expire))
```

校验：`ts = ULEB128 前缀`；`expire = ts + uint64(受托自己的 ttl)`；`now.UnixNano() > expire` 则过期；HMAC 与 `ServAddr18`（当前 QUIC 对端规范化）重算比对。`ServAddr` 是受托眼中的**源服务器**地址。

**Live Validation**（Unix **秒**）：

```
exp = uint64(now.Unix()) + uint64(distanceSec)
Validation = ULEB128(exp) || HMAC_SHA256(BaseKey, "STUN:Live.Port" || IP16 || Port2 || ULEB128(exp))
```

校验：`now.Unix() > Decode(前缀)` 则过期；HMAC 用请求中的 Address 重算。不另加时钟偏移预算。

`DelegateKey`、`BaseKey` 各 32 字节，由 server 在启动时生成或由应用注入；根包只管计算。

### 8. Equi-X

导入 `github.com/cxio/equix-cgo/puzz`。本库不实现 Equi-X，不直接调用 `github.com/cxio/equix-cgo` 根包（含 `Solve` / `SolveWithNonce`、HashWX 变体、自建 `Solver` / `Verifier`）。Nonce 搜索由 `puzz.Solve` / `puzz.SolveContext` 内部完成（步进 `0x26f5`）。

**种子**（传入 `Solve` / `Verify` 的 `challenge` 参数）为 SHA2-256 的 32 字节摘要，用 `crypto/sha256`：

```
KeyHash   = SHA256(Key32)                          // 受托侧直接使用请求中的 KeyHash
EquixSeed = SHA256(Challenge || Addr18 || KeyHash)
```

`Addr18` 为第 5 节规范化 18 字节。源服务器用连接上的 `ClientAddr`，受托用请求中的 `Target`，三者须为同一映射，否则校验失败。

**难度**（固定，不可配置）：

```go
const defaultRatio = 0.1
threshold, err := puzz.FromProbability(defaultRatio) // 0.1 合法；包级 init 失败则 panic
```

不用 `puzz.FromBits` / `puzz.DefaultBits`。`FromProbability` 对非法 `p` 返回 error，不得忽略后继续用零值门槛。

**调用**：

```go
soln, err := puzz.SolveContext(ctx, EquixSeed, threshold, 13) // 客户端；起始 nonce 固定为小素数 13
ok := puzz.Verify(EquixSeed, threshold, soln)                // 源服务器与受托
```

`puzz.Solution`：

```go
type Solution struct {
    Nonce    uint64
    Solution equix.Solution // [8]uint16
}
```

约定：

- 客户端对每份 Challenge 调用一次 `puzz.SolveContext`，传入本次探测的 `ctx`；起始 nonce 固定为小素数 `13`。库内路径禁止无取消的 `puzz.Solve`（测试可例外）。`err != nil`（含 `ctx` 取消）则本次探测返回 error，不伪造成 NAT 类型。取返回的 `*puzz.Solution`（含 Nonce 与解）。
- `puzz.Verify` 返回 `false`（哈希未达门槛或 Equi-X 结构不成立；`soln == nil` 亦为 false）在控制面上映射为 `VerifyFailed`。
- 控制面 **Solution** 16 字节用 `soln.Solution`（`equix.Solution`）的 `MarshalBinary` / `UnmarshalBinary`（little-endian `idx[0]…idx[7]`），不改字节序。
- 控制面 **Nonce** 为 8 字节**大端** `uint64`（与信封其它整数一致）；传入 `puzz.Solution.Nonce` 时用数值。puzz 内部把 nonce 以 8 字节 little-endian 拼进 Equi-X，不在本库。
- **禁止**把 `puzz.Solution.MarshalBinary()`（24 字节：LE Nonce + 16 字节解）当作控制面编码；那是 puzz 自己的便利格式，与本协议信封字段布局、Nonce 字节序都不同。
- 根包薄封装：`SolvePuzzle(ctx, seed)` → `puzz.SolveContext(ctx, seed, threshold, 13)`；`VerifyPuzzle(seed, soln)` → `puzz.Verify(seed, threshold, soln)`。只做 SHA-256 种子拼接、固定 threshold 与起始 nonce，以及这两次调用。
- 需要 `CGO_ENABLED=1`。

### 9. 判定矩阵（纯函数）

```go
// localEqual NewMap 时的本地比较
func ClassifyCone(newPort, newHost, localEqual bool) ConeKind
```

`ConeKind` 仅含：`FullCone`、`RC`、`PRC`、`OpenInternet`、`UDPFirewall`。矩阵见 SPEC-0003，与 DEC-0003 / `conelevel.md` 一致。`Sym-Like`、`QUIC Only` 由客户端状态机直接得出，不进入本函数。

### 10. 常量

**硬编码（不可配置）：**

| 名称 | 值 |
|------|----|
| `ProtocolVersion` | 1 |
| Passage 客户端/服务端超时 | 4s / 6s |
| Passage 探测包 | 2 个，间隔 100–300ms |
| NewPort 探测包 | 4 个，间隔 100–400ms |
| Live 收包超时（自发出 `STUN:Live` 请求） | 10s |
| Live 同一 Address 最小间隔 | 10s |
| Live 发送间隔表 (ms) | 100, 200, 400, 800, 1600, 1600, 1600, 1600（累计 7.9s） |
| 粗测起始间隔下限 | 10s |
| Validation `Distance` 上限 | 45 分钟（2700s） |
| Key32 / HMAC / SHA256 | 32 字节 |
| Equi-X 达标成功率 `defaultRatio` | 0.1（`puzz.FromProbability`，不可配置） |
| Equi-X 种子 | SHA-256（SHA-2，32 字节摘要） |
| Equi-X 起始 nonce | 13（小素数，不可配置） |
| TmpN 长度 | 16–1024 |
| 信封 MethodLen / Payload | 1–64 / ≤8192 |

**可配置（库给默认值）：**

| 名称 | 默认 |
|------|------|
| 预探测成功 `STUN:Addr` 数 | 3（不少于 3） |
| Inquire 抽选数 | 3（范围 2–3） |
| Inquire 收集超时 | 10s |
| 挑战 TTL | 2 分钟 |
| Cone 客户端回包超时 | 6s |
| 每台受托 NewHost 包数 | 3（上限 3，可向下配） |
| Live 单轮发包数 | 8（上限 8，可向下配，取间隔表前缀） |

粗测起始间隔**无默认值**，调用方必填，且 ≥ 10s。

**domainTag 字符串（精确）：**

- Cone SN：`STUN:Cone`
- Live SN 服务端：`Server@STUN:Live`
- Live SN 客户端：`Client@STUN:Live`
- Validation HMAC：`STUN:Live.Port`

### 11. `stun2` 导出

| 类别 | 符号 |
|------|------|
| 信封 | `EncodeRequest`、`DecodeRequest`、`EncodeResponse`、`DecodeResponse`；`Status`；第 3 节 sentinel |
| 地址 | `Addr`、`Normalize`、18 字节编解码、三种比较 |
| SN | Cone/Live 首字节盖戳、`BuildSN`、`VerifySN`、默认与可注入 `TmpNFunc` |
| 证明 | `IssueChallenge`、`VerifyChallenge`、`IssueValidation`、`VerifyValidation`、`KeyHash`、`EquixSeed`（SHA-256 拼接）、`SolvePuzzle` / `VerifyPuzzle` 薄封装（固定 `threshold`，起始 nonce `13`） |
| 判定 | `ClassifyCone`、`ConeKind` |
| 常量 | 第 10 节全部导出 |

根包**不得**导入 `quic-go`，不得做网络、计时、重试、节点发现。


## 边界与限制

- 节点发现、TLS 材料、双栈是否跑两遍、跨服务器聚合，均由应用负责。
- 受托连接池实现不在本包；接口在 SPEC-0003。
- 不直接使用 `github.com/cxio/equix-cgo` 根包的 HashWX API、包级 `Solve*` / `Verify*`、自建 `Solver` / `Verifier`。LGPL 源码随附义务不在本库实现范围；分发含 cgo 的二进制时由应用处理许可证。
- 握手期 ClientHello Equi-X 仍属上层，与 Cone 挑战路径分离。


## 待决问题

无。全局待决集为空。quic-go 关闭残留等待的具体调用见 SPEC-0004。


## 对 Plan 的约束

- 先实现并单测根包：信封往返、错误码、地址规范化、ULEB128 最简性、SN 首字节与 HMAC、Challenge / Validation 时间窗、`ClassifyCone` 五格、`EquixSeed` 拼接（SHA-256）。
- Equi-X 封装测试在 `CGO_ENABLED=1` 下调用真实 `github.com/cxio/equix-cgo/puzz`；用已知 Challenge / Addr / KeyHash 做 `SolvePuzzle`→`VerifyPuzzle` 往返；断言包级 `threshold` 等于 `puzz.FromProbability(0.1)` 的成功结果，起始 nonce 为 `13`。不在本库测试 nonce 搜索或 HashWX。控制面编解码测试必须用 16 字节 `equix.Solution` + 大端 Nonce，不得用 `puzz.Solution.MarshalBinary`。
- 不得在根包引入 IO。依赖：`github.com/cxio/equix-cgo/puzz` 与标准库 `crypto/sha256`；本阶段不引入 `quic-go`。
