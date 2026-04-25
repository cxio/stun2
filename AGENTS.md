# AGENTS.md

This file provides guidance to AI Agent when working with code in this repository.

## 项目简介

`stun2` 是一个用于检测 NAT 类型和 NAT 映射生命周期（lifetime）的 Go 库，基于改进的 STUN 协议设计，面向 P2P 服务网络。模块路径：`github.com/cxio/stun2`，Go 版本 1.26.2。

当前状态：设计完成，进入实现阶段（代码量极少，主要是类型定义和工具函数）。

## 常用命令

```bash
go build ./...          # 构建
go test ./...           # 运行全部测试
go test -run TestFoo    # 运行单个测试
go fmt ./...            # 格式化代码
go vet ./...            # 静态检查
go mod tidy             # 整理依赖
```

## 架构概览

### 核心数据类型（`natlevel.go`）

- **`NatLevel`**：NAT 等级枚举（-1 错误 / 0 Full Cone / 1 RC / 2 PRC / 3 Symmetric / 4 PRC|Sym）
- **`UDPSendi`**：服务端探测方式（本地地址 / 新端口 / 新主机）
- **`ClientSN [16]byte`**：客户端会话号，用于追踪探测消息
- **`Notice`**：STUN 服务器间协作通知

### 三阶段探测流程（详见 `docs/conception/design.md`）

1. **预检（STUN:Addr）**：客户端经 QUIC 连接两台不同 STUN 服务器，获取各自看到的公网地址，提前判断是否为对称 NAT。
2. **类型检测（STUN:Cone）**：客户端发送含 `Bas16` 的探测包；服务端通过 NewPort（同 IP 换端口）和 NewHost（不同 IP，可请求对等服务器协助）两种方式响应；客户端根据收到的响应模式判定 NAT 类型。消息认证使用哈希耦合 SN：`SN = Rnd16 + Hash256(Bas16 + Rnd16) + TmpN`。
3. **生命周期检测（STUN:Live）**：先粗检（15s 步长），再细检（3s 步长），每次探测发 3 个冗余包（间隔 100ms），确定 NAT 映射存活时长。

重传策略：指数退避，100ms → 1600ms，共 9 次，累计超时约 9.5s。
