# AGENTS.md

## 项目状态

设计阶段的 Go 库，**当前仓库尚无 Go 源码**（除 `go.mod`）。权威设计规格在 `docs/conception/`，实现前必读：

- `docs/conception/conelevel.md` — NAT 类型/层级探测协议（`STUN:Cone`）。
- `docs/conception/keepalive.md` — NAT 映射存活期探测协议（`STUN:Live`）。

实现新功能时，先以这两份文档为准；文档与代码冲突时以**已审定的文档**为准（提交历史显示文档经过多轮 AI 评审修订）。

- module: `github.com/cxio/stun2`，Go `1.26.2`。
- `docs/decision/`、`docs/plan/`、`docs/proposal/` 目前为空，是预留目录。

## 关键架构约束（容易做错）

- 这**不是** RFC 3489 STUN。探测流程基于「STUN 服务节点本身是一个 P2P 网络、节点间可相互协作发包」的前提重新设计，不要照搬传统 STUN 实现。
- 通信模式固定为 **QUIC 安全连接 + 底层裸 UDP socket 复用**：QUIC 负责安全传输，底层裸 UDP 用于 NAT 映射探测。
- 必须用 `quic-go` 库，且采用 `quic.Transport{Conn: udpConn}` + `Transport.ReadNonQUICPacket()` 模式，由外部传入 `net.UDPConn`（同一 socket 上同时跑 QUIC 与裸 UDP）。
- 服务节点信息（SPKI、ECH 公钥等）来自 [cxio/p2p](https://github.com/cxio/p2p) 项目，不在本库范围内。

## 协议实现要点（细节敏感，勿凭直觉）

### 会话标识 SN — 两套协议规则不同

两套协议 SN 前 48 字节均为 `Rnd16 + HMAC32`，`TmpN` 长度均为 464~1024（隐蔽长度特征）。但构造公式和 Rnd16 标志位有区别：

**Cone（`conelevel.md:§.会话标识`）**——不含地址，因为客户端无法预知受托服务器：
```
Rnd16[0] = Rnd16[0] & 0x3E | from   // from: 0=NewPort, 1=NewHost
SN = Rnd16 + HMAC_SHA256(Key, Rnd16 + TmpN) + TmpN
```

**Keepalive（`keepalive.md:§.会话标识`）**——含对端地址，可互相验证：
```
Rnd16[0] &= 0x3F                       // 仅高 2 位清零，无 NewPort/NewHost 标志
SN = Rnd16 + HMAC_SHA256(Key32, Rnd16 + LocalAddr + TmpN) + TmpN
```

### NewHost 密钥封装

`NewHost` 消息的 HMAC 密钥是 `SHA256(Key32)`，不是原始 `Key32`（防止受托服务器伪装客户端）。源服务器从本机新 IP 发送 `NewHost` 时**同样**使用封装后的密钥（`conelevel.md:108–116`）。

### 冗余发送 & 超时（两套协议不同）

**Cone**（`conelevel.md:§.消息发送；$.客户端超时`）：服务端发 **3** 次，间隔 `200ms, 400~800ms`，累计≤1s；客户端超时 **5 秒**。

**Keepalive**（`keepalive.md:$.服务端操作；$.探测循环`）：服务端发 **9** 次，间隔 `100, 200, 400, 800, 1600, 1600, 1600, 1600ms`，累计约 7.9s；客户端超时 **12 秒**。

每次重发都必须**新建 SN**，避免链路中间件合并/丢弃。

### 存活期探测参数

- 粗测间隔：**15s 倍增量**（15s→30s→60s→...），可配置。
- 精测按二分规则逼近，示例精度 **5s**（`keepalive.md:$.精测`），可配置。
- 起始间隔不低于 **10s**。

## 工作流

- 常用命令为标准 Go 工具链（`go build ./...`、`go test ./...`、`go vet ./...`），暂无自定义构建/CI/lint 配置。
- `go.sum` 已存在但为空；引入 `quic-go` 等依赖后需 `go mod tidy`。

## 约定

- 文档、注释、交互输出用简体中文；程序运行时消息/日志（`fmt`、`errors.New`、`log` 等实参）用英文。
- 标识符、目录/文件名、技术术语沿用英文。
