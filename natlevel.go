// Copyright (c) 2026 @cxio/stun2
// Released under the MIT license
//////////////////////////////////////////////////////////////////////////////
// NAT 探测协助包（UDP）
//
// 包含 NAT 类型探测所需的辅助结构和函数，
// 用于客户端与服务节点之间的UDP通信，以确定NAT类型。
//
//////////////////////////////////////////////////////////////////////////////

package stun2

import (
	"net"
)

// NatLevel NAT层级
type NatLevel int

// NAT 分层定义
const (
	NAT_LEVEL_ERROR  NatLevel = iota - 1 // -1: UDP不可用或探测错误
	NAT_LEVEL_PUB                        // 0: Public
	NAT_LEVEL_FULL                       // 1: Full Cone
	NAT_LEVEL_RC                         // 2: Restricted Cone (RC)
	NAT_LEVEL_PRC                        // 3: Port Restricted Cone (P-RC)
	NAT_LEVEL_SYM                        // 4: Symmetric NAT (Sym) | Sym UDP Firewall
	NAT_LEVEL_PRCSYM                     // 5: P-RC | Sym
)

// UDPSendi 服务器UDP发送方式
type UDPSendi int

// 发送操作
const (
	UDPSEND_LOCAL   UDPSendi = iota // UDP 发送：本地
	UDPSEND_NEWPORT                 // UDP 发送：新端口
	UDPSEND_NEWHOST                 // UDP 发送：新主机
)

// Notice 协作通知
// 当前服务节点向另一台服务器发送UDP协作要求（NewHost操作）。
type Notice struct {
	Op    UDPSendi     // UDP发送指示
	Addr  *net.UDPAddr // 目标客户端地址
	Bas16 []byte       // 客户端SN构造因子（16字节）
}

// 三个UDP消息置位标记
// 用于标识UDP消息类型（Listen, NewPort, NewHost），
// 设置在ClientSN首字节的低3位
const (
	bitListen  uint8 = 1 << iota // Listen UDP 本地发送
	bitNewPort                   // NewPort UDP 新端口发送
	bitNewHost                   // NewHost UDP 新主机发送
)
