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

- **会话标识 SN** 构造规则见 `conelevel.md` 第 60–89 行：`SN = Rnd16 + HMAC_SHA256(Key32, Rnd16 + LocalAddr + TmpN) + TmpN`，有效部分为前 48 字节，`TmpN` 长度 464~1024 用于隐藏长度特征。`Rnd16[0]` 的高 2 位、低 1 位有特定标志位语义（区分非 QUIC 包 / NewPort / NewHost）。
- `NewHost` 消息的 HMAC 密钥是 `SHA256(Key32)`，不是原始 `Key32`（防止受托服务器伪装客户端）。
- 冗余发送：100/200/400/800ms 逐次翻倍，之后封顶 1600ms 再发 5 次，共 9 次累计约 9500ms；客户端超时设为 **12 秒**（略大于服务端最大累计时长）。每次重发都要新建 SN，避免链路中间件合并/丢弃。
- 受托服务器（委托 `NewHost`）用 `Equi-X` PoW（`equix.Solve` / 验证解）做 DDoS 防范，源服务器与受托服务器间有一次 challenge 交互。
- 存活期探测的粗测精度 15s 增量、精测 3s 增量，起始间隔不低于 10s；这些应做成用户可配置项。

## 工作流

- 常用命令为标准 Go 工具链（`go build ./...`、`go test ./...`、`go vet ./...`），暂无自定义构建/CI/lint 配置。
- 无 `go.sum` 依赖记录，引入 `quic-go` 等依赖时需 `go mod tidy`。

## 约定

- 文档、注释、交互输出用简体中文；程序运行时消息/日志（`fmt`、`errors.New`、`log` 等实参）用英文。
- 标识符、目录/文件名、技术术语沿用英文。
