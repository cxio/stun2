# SPEC-0002 `STUN:Addr`

## 来源追溯

- `conception/pubaddr.md` 全文。
- `conception/conelevel.md`：预探测与正式探测均复用 `STUN:Addr`；正式探测在新 `ListenUDP` 上取映射。
- `conception/keepalive.md`：`STUN:Live.Port` 也返回观测地址，但是不同方法，见 SPEC-0004。
- `DEC-0001`：一次调用一个地址族；应用注入连接材料，库在已有 `quic.Conn` 上开 Stream；禁止 path migration。
- `DEC-0002`：信封与 Stream 用法见 SPEC-0001；本方法无额外失败类别。
- SPEC-0001：信封、18 字节地址、Version=1。


## 概述

`STUN:Addr` 是最基础的控制请求：服务器把当前这条 QUIC 连接对应的 UDP 对端地址（规范化后）返回给客户端。Cone 预探测、Cone 正式探测创建映射，都调用本方法。它本身不读裸 UDP。


## 规格正文

### 1. 载荷

**请求 Payload：** 空。

**响应 Payload（Status=0）：** 18 字节 `Addr`（SPEC-0001 §5）。

服务器从 `conn.RemoteAddr()` 取出 UDP 对端，经 `Normalize` 后写入。总能成功，除非 Version 不支持（`UnsupportedVersion`）或请求 Payload 非空（`InvalidPayload`）。

### 2. 客户端

```go
func GetAddr(ctx context.Context, conn *quic.Conn) (stun2.Addr, error)
```

在 `conn` 上 `OpenStreamSync`，发送 `STUN:Addr` 请求，读响应，关闭 Stream。不创建、不关闭 `conn`。

`DialUDP` 或 `ListenUDP` 之上的 QUIC 均可。要测 IPv4 必须显式用 IPv4 拨号；库不因系统优先 IPv6 而改族。

用途（由调用方或 Cone/Live 状态机使用，本函数只返回地址）：

- 与本机 Socket 源地址 `Equal`：公网直连判断（`STUN:Live` 预探测；`STUN:Cone` 正式探测的 NewMap 比较）。
- `EqualIP`：出口 IP 是否仍是同一公网 IP。
- `EqualPort`：`STUN:Cone` 预探测按端口排除 `Sym-Like`。

> **注意：**
> 参与比较的本机地址必须取实际网卡的通讯 IP（按目的路由解析或显式指定绑定），禁止通配的 `0:0:0:0` / `[::]`（见 `pubaddr.md` 注意）。

### 3. 服务端

`stun2/server` 在已接受的 `quic.Conn` 上按 Stream 分派。收到 `STUN:Addr` 即观测对端并响应。不建表，不发裸 UDP。

同一连接上可并发多条 Stream；本方法与其它方法无队头依赖。

### 4. 连接与迁移

本方法使用调用方已有连接。库不得对该连接调用 `AddPath`。若应用在探测过程中发生连接迁移，观测地址与 SN 所用四元组可能分家；此为应用违规，结果不作数。


## 边界与限制

- 不发现节点、不拨号、不配置 ALPN。
- 不判断 NAT 类型；只返回一个地址。
- 双栈由调用方跑两遍。


## 待决问题

无。


## 对 Plan 的约束

- 在 SPEC-0001 根包测试通过后实现。
- 先写客户端编解码 + 假连接（或 `quic.Conn` 替身）往返测试，再写服务端 handler：给定 `RemoteAddr`，响应必须是规范化 18 字节。
- IPv4 拨号必须得到 mapped 形式；原生 IPv6 原样。
- 本阶段仍可不引入真实网络；用可注入的 `RemoteAddr` 即可。
