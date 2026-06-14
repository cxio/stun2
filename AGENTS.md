# AGENTS.md

## 项目简介

`stun2` 是一个用于检测 NAT 类型和 NAT 映射生命周期（lifetime）的 Go 库，面向 P2P 服务网络。模块路径：`github.com/cxio/stun2`，Go 版本 1.26.2。

**当前状态：设计阶段。** 项目中暂无可编译的 Go 源码，仅设计文档就位。实现将从零开始。

## 常用命令

以下命令在当前无 Go 源码的状态下会失败。代码就位后可用：

```bash
go build ./...          # 构建
go test ./...           # 运行全部测试
go test -run TestFoo    # 运行单个测试
go fmt ./...            # 格式化代码
go vet ./...            # 静态检查
go mod tidy             # 整理依赖
```

## 架构概览

### 设计文档

设计文档位于 `docs/conception/design.md`，是三阶段探测流程的权威规范。**所有实现必须与此文档对齐。**

### 三阶段探测流程

1. **预探测（STUN:Addr）**：客户端经 QUIC 连接两台不同 STUN 服务器，获取各自看到的公网地址。两地址不同则判定 Symmetric NAT，提前结束。
2. **类型检测（STUN:Cone）**：客户端发送含 `Bas16`（16 字节）的探测包；服务端通过 NewPort（同 IP 换端口）和 NewHost（不同 IP）两种方式响应；客户端根据收到的响应判定 NAT 类型。
3. **生命周期检测（STUN:Live）**：先粗检（15s 步长），再细检（3s 步长），确定 NAT 映射存活时长。

### 核心协议细节

- **通信模式**：QUIC 安全连接 + 裸 UDP 混合。`Bas16` 等敏感数据通过 QUIC 传递；探测包通过裸 UDP 发送。
- **SN 构造**：`Rnd16[0] = Rnd16[0] & 0xF8 | flag`，其中 `flag` 为 `bitListen`/`bitNewPort`/`bitNewHost`（互斥，占低 3 位）。完整 SN = `Rnd16 + Hash256(Bas16 + Rnd16) + TmpN`，前 48 字节为有效载荷。
- **重传策略**：指数退避 100ms → 1600ms，共 9 次，累计超时约 9.5s。客户端超时 10s。每次发送追加 1 个冗余包（Cone）；Live 阶段每次 3 个包（2 冗余），间隔 100ms。
- **服务端协作**：NewHost 可通过请求对等服务器协助实现（`Notice` 结构承载协作数据）。

### 判断矩阵（最终 NAT 类型）

| NewPort 收到 | NewHost 收到 | 预探测地址相同 | 结果 |
|:---:|:---:|:---:|------|
| Y | - | N | RC 或 FullC（待 NewHost 覆盖） |
| N | - | - | P-RC |
| - | Y | N | Full Cone |
| - | Y | Y | Open Internet（Public） |
| - | N | Y | UDP Firewall |

## 代码规范（编写 Go 源码时遵循）

- **常量命名**：使用 `MixedCaps`（导出）或 `mixedCaps`（未导出），禁止 `ALL_CAPS`。如 `NatLevelError` 而非 `NAT_LEVEL_ERROR`。
- **固定长度数据**：`Bas16` 等 16 字节定长数据用 `[16]byte` 而非 `[]byte`，编译期保证长度正确。
- **类型定义**：为关键标识定义具名类型（如 `type Bas16 [16]byte`）以增强类型安全。
- **依赖**：优先使用标准库（如 `crypto/sha256`），未确认收益前不引入第三方依赖。

## 目录结构

```
docs/conception/design.md   # 权威设计文档（375 行）
docs/plan/                  # 空，规划阶段
docs/decision/              # 空，决策记录
docs/proposal/              # 空，提案阶段
```
