# AGENTS.md - stun2 代码库指南

> 本文档为 AI 编码助手提供项目规范和最佳实践指南

## 通用约束

请尽可能使用中文交互和书写。

对于规范文档（*.md）以及其它文档，必须使用英文的地方，维持英语习惯：如约定的命名、术语、文件名等。

文档内容主体中的标题可以使用惯用的英文表达，段落中的缩略词、专有名词等也同样（更准确）。其它描述性内容则应当使用中文，以便于用户阅读、理解和修改。

如果与用户的交互中需要引用文档中的英文标题，应当在英文之后附上中文（翻译在括号内）。

> **注：**
> 本约束条目（`## 通用约束`）请勿在后续的自动修改中移除。


## 项目概览

**stun2** 是一个新型的 NAT 类型探测库，基于 P2P STUN 服务节点网络。项目使用 Go 语言编写，采用 UDP 和 QUIC 混合通信模式进行 NAT 探测。

- **语言**: Go 1.25.5
- **模块路径**: `github.com/cxio/stun2`
- **许可证**: MIT License
- **主要功能**: NAT 类型探测、存活期探测

---

## 构建与测试

### 基础命令

```bash
# 构建项目
go build ./...

# 运行所有测试
go test ./...

# 运行测试并显示详细输出
go test -v ./...

# 运行测试并生成覆盖率报告
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out  # 查看覆盖率报告

# 运行单个包的测试
go test -v .

# 运行单个测试函数
go test -v -run TestFunctionName

# 运行匹配模式的测试
go test -v -run "TestNAT.*"

# 基准测试
go test -bench=.
go test -bench=BenchmarkSpecific -benchmem
```

### 代码检查与格式化

```bash
# 格式化代码（自动修复）
gofmt -w .

# 检查格式化差异（不修改文件）
gofmt -d .

# 列出需要格式化的文件
gofmt -l .

# 静态分析和常见错误检查
go vet ./...

# 下载依赖
go mod download

# 整理依赖（移除未使用的依赖）
go mod tidy

# 验证依赖
go mod verify
```

---

## 代码规范

### 文件组织

- **命名约定**: 使用小写字母和下划线，如 `natlevel.go`
- **测试文件**: 以 `_test.go` 结尾
- **包声明**: 每个文件开头声明 `package stun2`
- **文件头部**: 包含版权信息和文件用途说明

```go
// Copyright (c) 2026 @cxio/stun2
// Released under the MIT license
//////////////////////////////////////////////////////////////////////////////
//
// NAT 探测协助包（UDP）
//
// 包含 NAT 类型探测所需的辅助结构和函数，
// 用于客户端与服务节点之间的UDP通信，以确定NAT类型。
//
//////////////////////////////////////////////////////////////////////////////

package stun2
```

### 导入规范

导入顺序：
1. 标准库
2. 第三方库
3. 本地包

```go
import (
    "net"
    "net/netip"
)
```

### 命名约定

- **常量**: 使用全大写下划线分隔 `NAT_LEVEL_ERROR`, `UDPSEND_LOCAL`
- **类型**: 使用驼峰命名 `NatLevel`, `UDPSendi`, `ClientSN`
- **函数**: 导出函数使用大写开头 `AddrPort`, `NewUDPAddr`；私有函数小写开头 `equalAddrUDP`
- **变量**: 使用驼峰命名，简洁明了

### 类型定义

使用显式类型定义增强类型安全：

```go
// NatLevel NAT层级
type NatLevel int

// UDPSendi 服务器UDP发送方式
type UDPSendi int

// ClientSN 客户端序列号类型
type ClientSN [16]byte
```

### 常量组

使用 `iota` 定义枚举常量：

```go
const (
    NAT_LEVEL_ERROR  NatLevel = iota - 1  // -1: UDP不可用或探测错误
    NAT_LEVEL_NULL                        // 0:  Public | Public@UPnP | Full Cone
    NAT_LEVEL_RC                          // 1:  Restricted Cone (RC)
    NAT_LEVEL_PRC                         // 2:  Port Restricted Cone (P-RC)
    NAT_LEVEL_SYM                         // 3:  Symmetric NAT (Sym)
)
```

### 注释规范

- **包注释**: 在包声明前用多行注释描述包用途
- **函数注释**: 导出函数必须有注释，描述功能、参数和返回值
- **行内注释**: 重要逻辑和常量需要说明性注释
- **中文注释**: 本项目使用中文注释，保持清晰易懂

```go
// AddrPort 解析通用地址内的IP和端口
// 如果实参包含的是 IPAddr，端口号返回-1。
// 其它类型地址会导致恐慌。
// @addr 网络地址（非UnixAddr）
// @return1 IP地址
// @return2 端口
func AddrPort(addr net.Addr) (netip.Addr, int) {
    // 实现...
}
```

### 错误处理

- 使用 `panic` 处理不可恢复的错误（如类型断言失败）
- 返回 `error` 类型处理可预期的错误
- 使用错误级别常量表示状态（如 `NAT_LEVEL_ERROR`）

```go
default:
    panic("Bad net.Addr format.")
```

### 结构体定义

- 字段名称清晰明确
- 添加字段注释说明用途
- 按照逻辑分组组织字段

```go
// Notice 协作通知
// 当前服务节点向另一台服务器发送UDP协作要求（NewHost操作）。
type Notice struct {
    Op   UDPSendi     // UDP发送指示
    Addr *net.UDPAddr // 目标客户端地址
    SN   ClientSN     // 待发送内容
}
```

---

## 架构设计

### 核心概念

1. **NAT 类型**: Full Cone, Restricted Cone, Port Restricted Cone, Symmetric
2. **探测流程**: 预探测 → 正式探测 → 综合判断
3. **通信模式**: QUIC 安全连接 + 纯 UDP 探测混合模式
4. **会话标识**: 使用哈希耦合的 SN 构造规则确保安全性

### 关键文件

- `natlevel.go` - NAT 层级定义和辅助函数
- `stun2.proto` - Protocol Buffers 消息定义
- `design.md` - 详细的技术文档和探测流程说明
- `README.md` - 项目概览和使用说明

---

## 协议缓冲区

项目使用 Protocol Buffers (proto3) 定义消息格式：

```bash
# 生成 Go 代码
protoc --go_out=. stun2.proto
```

主要消息类型：
- `PUAddr` - 节点 UDP 地址
- `LiveNAT` - 存活期探测信息（client to server）
- `HostTo` - NewHost 协助消息发送

---

## Git 提交规范

参考项目历史提交记录：

```bash
# 查看提交历史
git log --oneline

# 提交格式
git commit -m "简短描述修改内容"

# 示例
git commit -m "mini fixed."
git commit -m "修订，基本完成。"
```

---

## 最佳实践

1. **保持简洁**: 函数职责单一，逻辑清晰
2. **类型安全**: 使用明确的类型定义，避免裸类型
3. **文档先行**: 复杂逻辑先更新 design.md 文档或 README.md 说明
4. **测试驱动**: 编写测试覆盖关键功能
5. **代码审查**: 提交前运行 `go vet` 和 `gofmt`
6. **依赖管理**: 使用 `go mod` 管理依赖，保持 go.sum 同步

---

## 常见任务

### 添加新功能

1. 定义相关类型和常量
2. 实现核心函数
3. 编写测试用例
4. 更新文档注释和项目使用说明（README.md）

### 调试技巧

```bash
# 运行测试并显示详细日志
go test -v -run TestSpecific

# 使用 delve 调试器
dlv test -- -test.run TestSpecific
```

### 性能优化

```bash
# 性能分析
go test -cpuprofile=cpu.prof -memprofile=mem.prof -bench=.
go tool pprof cpu.prof
```

---

## 注意事项

- **网络安全**: 注意 UDP 消息的验证，防止重放攻击
- **并发安全**: 处理并发场景时注意使用 channel 或锁
- **资源管理**: 及时关闭连接和释放资源
- **超时处理**: 网络操作设置合理的超时时间
- **错误处理**: 不要忽略错误，合理处理各种异常情况

---

## 参考资源

- [Go 语言规范](https://go.dev/ref/spec)
- [Effective Go](https://go.dev/doc/effective_go)
- [RFC 3489 - STUN](https://datatracker.ietf.org/doc/html/rfc3489)
- [项目 design](./design.md) - 详细的 NAT 探测设计文档

---

**最后更新**: 2026-01-16
