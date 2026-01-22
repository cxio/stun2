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

import (
	"net"
	"net/netip"
)

// NatLevel NAT层级
type NatLevel int

// NAT 分层定义
const (
	NAT_LEVEL_ERROR  NatLevel = iota - 1 // -1: UDP不可用或探测错误
	NAT_LEVEL_NULL                       // 0:  Public | Public@UPnP | Full Cone
	NAT_LEVEL_RC                         // 1:  Restricted Cone (RC)
	NAT_LEVEL_PRC                        // 2:  Port Restricted Cone (P-RC)
	NAT_LEVEL_SYM                        // 3:  Symmetric NAT (Sym) | Sym UDP Firewall
	NAT_LEVEL_PRCSYM                     // 4:  P-RC | Sym
)

// UDPSendi 服务器UDP发送方式
type UDPSendi int

// 发送操作
const (
	UDPSEND_LOCAL   UDPSendi = iota // UDP 发送：本地
	UDPSEND_NEWPORT                 // UDP 发送：新端口
	UDPSEND_NEWHOST                 // UDP 发送：新主机
)

// ClientSN 客户端序列号类型。
type ClientSN [16]byte

// Notice 协作通知
// 当前服务节点向另一台服务器发送UDP协作要求（NewHost操作）。
type Notice struct {
	Op   UDPSendi     // UDP发送指示
	Addr *net.UDPAddr // 目标客户端地址
	SN   ClientSN     // 待发送内容
}

// 三个UDP消息置位标记
// 用于标识UDP消息类型（Listen, NewPort, NewHost），
// 设置在ClientSN首字节的低3位
const (
	bitListen  uint8 = 1 << iota // Listen UDP 本地发送
	bitNewPort                   // NewPort UDP 新端口发送
	bitNewHost                   // NewHost UDP 新主机发送
)

//
// 辅助工具
//////////////////////////////////////////////////////////////////////////////
//

// AddrPort 解析通用地址内的IP和端口
// 如果实参包含的是 IPAddr，端口号返回-1。
// 其它类型地址会导致恐慌。
// @addr 网络地址（非UnixAddr）
// @return1 IP地址
// @return2 端口
func AddrPort(addr net.Addr) (netip.Addr, int) {
	var ap netip.AddrPort

	switch x := addr.(type) {
	case *net.TCPAddr:
		ap = x.AddrPort()
	case *net.UDPAddr:
		ap = x.AddrPort()
	case *net.IPAddr:
		ip, _ := netip.AddrFromSlice(x.IP)
		return ip, -1
	default:
		panic("Bad net.Addr format.")
	}
	return ap.Addr(), int(ap.Port())
}

// NewUDPAddr 创建一个新UDP地址。
// 仅取实参地址的IP，用一个新的端口号构建。
// @addr 网络地址（非UnixAddr）
// @port 新的端口号
// @return 一个新的UDP地址
func NewUDPAddr(addr net.Addr, port int) *net.UDPAddr {
	ip, _ := AddrPort(addr)

	return &net.UDPAddr{
		IP:   ip.AsSlice(),
		Port: port,
	}
}

//
// 私有辅助部分
//////////////////////////////////////////////////////////////////////////////
//

// 比较两个UDP地址相等性。
func equalAddrUDP(addr1, addr2 *net.UDPAddr) bool {
	if addr1 == nil || addr2 == nil {
		return addr1 == addr2
	}
	return addr1.IP.Equal(addr2.IP) && addr1.Port == addr2.Port
}
