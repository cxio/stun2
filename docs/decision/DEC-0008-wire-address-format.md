# 0008 — 控制消息中的地址编码格式（`WireAddr`）

## 背景

`conelevel.md`"公网NAT映射地址获取"节说明 `STUN:Addr` 返回的地址"可以是 IPv6……也可以是 IPv4"，但未定义控制消息中 `IP:Port` 的具体二进制编码；`DEC-0001` §「Wire Format」已把"各字段的二进制布局：`IP`、`Port`……"列为协议层必须定义的内容。此前 `proposal/wire-spec-v1.md` §3 已给出一套具体编码，本决策正式收编，并使其与 SN 内 `LocalIP` 字段（`DEC-0004`、`keepalive.md`）保持同族表示，降低实现复杂度。

## 决策

所有控制消息中出现的 `IP:Port` 组合 **MUST** 使用定长 **18 字节** 的 `WireAddr` 编码：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 16 | `IP` | IPv6 地址，或 IPv4-mapped IPv6 形式 |
| 16 | 2 | `Port` | UDP 端口号（`uint16`，大端） |

- **IPv4** **MUST** 编码为 IPv4-mapped IPv6：`::ffff:a.b.c.d`（前 10 字节为 `0`，第 11–12 字节为 `0xFF 0xFF`，后 4 字节为 IPv4 地址）。
- **IPv6** 使用标准 16 字节地址表示。

此编码与 SN 内 `LocalIP` 字段（16 字节、不含 `Port`，见 `keepalive.md`"会话标识"节 与 `DEC-0004`）共用同一套 IP 表示规则，仅 `WireAddr` 额外携带 2 字节 `Port`。

## 理由

- 定长编码解析简单、无需长度前缀，适合作为控制消息中反复出现的基础组件。
- 复用 SN 已经确定的 IPv4-mapped IPv6 方案，避免协议内出现两套不同的地址表示法，降低实现和测试成本。

## 影响范围

- **Proposal**：`wire-spec-v1.md` §3 中已有的 `WireAddr` 编码由本决策正式背书。
- 用于 `DEC-0009` 中 `STUN:Addr` 的 `ADDR_RESP` 及其他控制消息中出现的地址字段。
