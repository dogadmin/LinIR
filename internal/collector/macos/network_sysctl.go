//go:build darwin

package macos

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/dogadmin/LinIR/internal/model"
)

// collectSysctlConnections 通过 sysctl pcblist_n 采集全系统 TCP/UDP 连接。
//
// 使用 pcblist_n 格式（Apple netstat 使用的同一接口），优势：
//   - 类型化子记录（xgn_kind 标识），不再需要字节模式扫描
//   - 地址/端口在 xinpcb_n 中的固定偏移
//   - TCP 状态在 xtcpcb_n 中的固定偏移
//   - 包含 PID 信息（xsocket_n.so_last_pid）
//   - 单次 sysctl 调用同时返回 IPv4 和 IPv6 连接
//
// 参考: XNU bsd/netinet/in_pcb.h, bsd/sys/socketvar.h, bsd/netinet/tcp_var.h
//       Apple network_cmds/netstat.tproj/inet.c
func collectSysctlConnections(ctx context.Context) ([]model.ConnectionInfo, error) {
	var conns []model.ConnectionInfo

	pcbSources := []struct {
		sysctl string
		proto  string
	}{
		{"net.inet.tcp.pcblist_n", "tcp"},
		{"net.inet.udp.pcblist_n", "udp"},
	}

	for _, src := range pcbSources {
		select {
		case <-ctx.Done():
			return conns, ctx.Err()
		default:
		}
		raw, err := unix.SysctlRaw(src.sysctl)
		if err == nil && len(raw) > 0 {
			conns = append(conns, parsePcbListN(raw, src.proto)...)
		}
	}

	if len(conns) == 0 {
		return nil, fmt.Errorf("sysctl pcblist_n 未返回任何连接")
	}

	return conns, nil
}

// pcblist_n 子记录类型常量 (XNU bsd/sys/socketvar.h)
const (
	xsoSocket = 0x001
	xsoInpcb  = 0x010
	xsoTcpcb  = 0x020
)

// parsePcbListN 解析 pcblist_n 格式的二进制数据。
//
// 格式: [xinpgen header] [sub-record 1] [sub-record 2] ... [xinpgen footer]
// 每条连接由多个子记录组成，通过 xgn_kind 位标志收集齐后输出。
func parsePcbListN(raw []byte, proto string) []model.ConnectionInfo {
	if len(raw) < 24 {
		return nil
	}

	// xinpgen header: 前 4 字节 = 长度
	headerLen := binary.LittleEndian.Uint32(raw[0:4])
	if headerLen < 8 || int(headerLen) > len(raw) {
		return nil
	}

	var conns []model.ConnectionInfo

	// 收集状态：每条连接的子记录
	var curSocket *pcbSocketInfo
	var curInpcb *pcbInpcbInfo
	var curTcpState int32 = -1
	collected := uint32(0)

	// 确定"齐全"标志
	allKindInp := uint32(xsoSocket | xsoInpcb)
	allKindTcp := uint32(xsoSocket | xsoInpcb | xsoTcpcb)
	needAll := allKindInp
	if proto == "tcp" {
		needAll = allKindTcp
	}

	pos := roundup64(headerLen)

	for int(pos)+8 <= len(raw) {
		xgnLen := binary.LittleEndian.Uint32(raw[pos : pos+4])
		xgnKind := binary.LittleEndian.Uint32(raw[pos+4 : pos+8])

		if xgnLen <= headerLen {
			break // footer
		}
		if int(pos+xgnLen) > len(raw) {
			break
		}

		rec := raw[pos : pos+xgnLen]

		switch xgnKind {
		case xsoSocket:
			curSocket = parseSocketN(rec)
			collected |= xsoSocket
		case xsoInpcb:
			curInpcb = parseInpcbN(rec)
			collected |= xsoInpcb
		case xsoTcpcb:
			curTcpState = parseTcpcbN(rec)
			collected |= xsoTcpcb
		}

		// 当所有子记录收齐，输出一条连接
		if collected&needAll == needAll {
			if curInpcb != nil {
				conn := buildConnection(curSocket, curInpcb, curTcpState, proto)
				if conn != nil {
					conns = append(conns, *conn)
				}
			}
			// 重置
			curSocket = nil
			curInpcb = nil
			curTcpState = -1
			collected = 0
		}

		pos += roundup64(xgnLen)
	}

	return conns
}

func roundup64(x uint32) uint32 {
	return (x + 7) &^ 7
}

// ========== 子记录解析 ==========

type pcbSocketInfo struct {
	pid    int32
	ePid   int32
	family int32
}

type pcbInpcbInfo struct {
	fport  uint16 // foreign port (网络字节序)
	lport  uint16 // local port (网络字节序)
	vflag  uint8  // INP_IPV4=0x1, INP_IPV6=0x2
	faddr4 net.IP // IPv4 foreign addr
	laddr4 net.IP // IPv4 local addr
	faddr6 net.IP // IPv6 foreign addr
	laddr6 net.IP // IPv6 local addr
}

// parseSocketN 从 xsocket_n 子记录中提取 PID 和协议族。
//
// struct xsocket_n {
//   u32 xso_len;           // +0
//   u32 xso_kind;          // +4
//   u64 xso_so;            // +8
//   i16 so_type;           // +16
//   u32 so_options;        // +20 (aligned)
//   i16 so_linger;         // +24
//   i16 so_state;          // +26
//   u64 so_pcb;            // +28 (aligned to 8? actually +32)
//   i32 xso_protocol;      // +40
//   i32 xso_family;        // +44
//   ... more fields ...
//   pid_t so_last_pid;     // varies by version
//   pid_t so_e_pid;
// };
//
// 由于 struct packing 和版本差异，我们用安全扫描法提取 PID。
func parseSocketN(rec []byte) *pcbSocketInfo {
	if len(rec) < 48 {
		return nil
	}
	info := &pcbSocketInfo{}

	// xso_family 在偏移 44 (确定字段)
	info.family = int32(binary.LittleEndian.Uint32(rec[44:48]))

	// so_last_pid 和 so_e_pid 是 xsocket_n 的最后两个字段 (macOS 10.15+)
	// xsocket_n 典型大小 160-176 字节，至少 80 字节才可能包含 PID 字段
	recLen := len(rec)
	if recLen >= 80 {
		info.ePid = int32(binary.LittleEndian.Uint32(rec[recLen-4:]))
		info.pid = int32(binary.LittleEndian.Uint32(rec[recLen-8:]))
		// 校验：PID 应该 >= 0 且合理
		if info.pid < 0 || info.pid > 1000000 {
			info.pid = 0
		}
		if info.ePid < 0 || info.ePid > 1000000 {
			info.ePid = 0
		}
		// 备用偏移：某些 macOS 版本 struct 对齐不同，PID 在 recLen-12 / recLen-8
		if info.pid == 0 && info.ePid == 0 && recLen >= 84 {
			altPid := int32(binary.LittleEndian.Uint32(rec[recLen-12:]))
			altEPid := int32(binary.LittleEndian.Uint32(rec[recLen-8:]))
			if altPid > 0 && altPid <= 1000000 {
				info.pid = altPid
			}
			if altEPid > 0 && altEPid <= 1000000 {
				info.ePid = altEPid
			}
		}
	}

	return info
}

// inpcbOffsets 定义 xinpcb_n 中各字段的偏移量。
// 不同 macOS 版本的结构体布局可能不同。
type inpcbOffsets struct {
	fport int // inp_fport (u16, big-endian)
	lport int // inp_lport (u16, big-endian)
	vflag int // inp_vflag (u8)
	faddr int // inp_dependfaddr union (16 bytes)
	laddr int // inp_dependladdr union (16 bytes)
	ipv4Off int // IPv4 地址在 union 内的偏移（in_addr_4in6 中 pad[3] 之后）
}

// 已知的偏移配置，按 macOS 版本从新到旧排列
var knownInpcbOffsets = []inpcbOffsets{
	// 配置 A: macOS 10.15-12 (标准布局)
	{fport: 16, lport: 18, vflag: 48, faddr: 52, laddr: 68, ipv4Off: 12},
	// 配置 B: 偏移漂移 +8 (某些 macOS 13+ 版本)
	{fport: 24, lport: 26, vflag: 56, faddr: 60, laddr: 76, ipv4Off: 12},
	// 配置 C: 偏移漂移 -8
	{fport: 12, lport: 14, vflag: 44, faddr: 48, laddr: 64, ipv4Off: 12},
}

// 缓存探测到的正确偏移
var detectedOffsets *inpcbOffsets

// parseInpcbN 从 xinpcb_n 子记录中提取地址和端口。
// 使用多偏移探测机制：尝试已知的偏移配置，通过 vflag 有效性校验选出正确的一组。
func parseInpcbN(rec []byte) *pcbInpcbInfo {
	if len(rec) < 40 {
		return nil
	}

	// 如果已探测到正确偏移，直接使用
	if detectedOffsets != nil {
		return extractInpcb(rec, detectedOffsets)
	}

	// 尝试每组已知偏移
	for i := range knownInpcbOffsets {
		off := &knownInpcbOffsets[i]
		if off.laddr+16 > len(rec) {
			continue
		}
		vf := rec[off.vflag]
		// vflag 有效值: 0x1(IPv4), 0x2(IPv6), 0x3(双栈)
		if vf == 0x1 || vf == 0x2 || vf == 0x3 {
			// 额外验证: 端口至少有一个非零
			fport := binary.BigEndian.Uint16(rec[off.fport : off.fport+2])
			lport := binary.BigEndian.Uint16(rec[off.lport : off.lport+2])
			if fport > 0 || lport > 0 {
				detectedOffsets = off
				return extractInpcb(rec, off)
			}
		}
	}

	// 所有已知偏移都失败，暴力搜索 vflag 位置
	// 在记录中搜索值为 0x1/0x2/0x3 的字节，前面 2+2 字节为有效端口
	for vpos := 20; vpos+36 <= len(rec); vpos++ {
		vf := rec[vpos]
		if vf != 0x1 && vf != 0x2 && vf != 0x3 {
			continue
		}
		// vflag 前面应该是: fport(-32), lport(-30), ... , vflag
		// 但距离不确定。尝试常见的模式: vflag 前面有 flow(4)+flags(4)=8 字节,
		// 再前面是 gencnt(8)+ppcb(8)=16 字节, 再前面是端口 (vflag - 32)
		portOff := vpos - 32
		if portOff < 8 || portOff+4 > len(rec) {
			continue
		}
		fport := binary.BigEndian.Uint16(rec[portOff : portOff+2])
		lport := binary.BigEndian.Uint16(rec[portOff+2 : portOff+4])
		if (fport > 0 || lport > 0) && fport < 65535 && lport < 65535 {
			addrOff := vpos + 4 // vflag(1)+ttl(1)+proto(1)+pad(1) = 4 bytes
			if addrOff+32 <= len(rec) {
				off := &inpcbOffsets{
					fport:   portOff,
					lport:   portOff + 2,
					vflag:   vpos,
					faddr:   addrOff,
					laddr:   addrOff + 16,
					ipv4Off: 12,
				}
				detectedOffsets = off
				return extractInpcb(rec, off)
			}
		}
	}

	return nil
}

func extractInpcb(rec []byte, off *inpcbOffsets) *pcbInpcbInfo {
	if off.laddr+16 > len(rec) {
		return nil
	}

	info := &pcbInpcbInfo{}
	info.fport = binary.BigEndian.Uint16(rec[off.fport : off.fport+2])
	info.lport = binary.BigEndian.Uint16(rec[off.lport : off.lport+2])
	info.vflag = rec[off.vflag]

	// Foreign address
	if off.faddr+off.ipv4Off+4 <= len(rec) {
		info.faddr4 = net.IPv4(
			rec[off.faddr+off.ipv4Off],
			rec[off.faddr+off.ipv4Off+1],
			rec[off.faddr+off.ipv4Off+2],
			rec[off.faddr+off.ipv4Off+3])
	}
	info.faddr6 = make(net.IP, 16)
	copy(info.faddr6, rec[off.faddr:off.faddr+16])

	// Local address
	if off.laddr+off.ipv4Off+4 <= len(rec) {
		info.laddr4 = net.IPv4(
			rec[off.laddr+off.ipv4Off],
			rec[off.laddr+off.ipv4Off+1],
			rec[off.laddr+off.ipv4Off+2],
			rec[off.laddr+off.ipv4Off+3])
	}
	info.laddr6 = make(net.IP, 16)
	copy(info.laddr6, rec[off.laddr:off.laddr+16])

	return info
}

// parseTcpcbN 从 xtcpcb_n 子记录中提取 TCP 状态。
//
// struct xtcpcb_n {
//   u32 xt_len;     // +0
//   u32 xt_kind;    // +4 (XSO_TCPCB)
//   i32 t_state;    // +8
//   ... more TCP fields ...
// };
func parseTcpcbN(rec []byte) int32 {
	if len(rec) < 12 {
		return -1
	}
	return int32(binary.LittleEndian.Uint32(rec[8:12]))
}

// ========== 构建连接 ==========

func buildConnection(sock *pcbSocketInfo, inp *pcbInpcbInfo, tcpState int32, proto string) *model.ConnectionInfo {
	var localIP, remoteIP net.IP
	var family string

	if inp.vflag&0x1 != 0 {
		localIP = inp.laddr4
		remoteIP = inp.faddr4
		family = "ipv4"
	} else if inp.vflag&0x2 != 0 {
		// macOS 双栈：大量 IPv4 连接以 IPv4-mapped IPv6 (::ffff:x.x.x.x) 存储
		if inp.faddr6.To4() != nil || inp.laddr6.To4() != nil {
			localIP = inp.laddr4
			remoteIP = inp.faddr4
			family = "ipv4"
		} else {
			localIP = inp.laddr6
			remoteIP = inp.faddr6
			family = "ipv6"
		}
	} else {
		return nil
	}

	// 跳过全零未绑定 socket
	if inp.lport == 0 && inp.fport == 0 {
		return nil
	}

	conn := &model.ConnectionInfo{
		Proto:         proto,
		Family:        family,
		LocalAddress:  localIP.String(),
		LocalPort:     inp.lport,
		RemoteAddress: remoteIP.String(),
		RemotePort:    inp.fport,
		Source:        "sysctl_pcblist_n",
		Confidence:    "high",
	}

	// PID
	if sock != nil {
		pid := int(sock.pid)
		if pid <= 0 {
			pid = int(sock.ePid)
		}
		if pid > 0 {
			conn.PID = pid
		}
	}
	if conn.PID == 0 {
		conn.Confidence = "medium"
	}

	// TCP state
	if proto == "tcp" && tcpState >= 0 {
		conn.State = tcpStateName(tcpState)
	} else if proto == "udp" {
		conn.State = "STATELESS"
	} else {
		conn.State = "UNKNOWN"
	}

	return conn
}
