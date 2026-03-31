//go:build darwin

package macos

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ========== proc_info syscall 常量 ==========
// 来源: XNU bsd/sys/proc_info.h

const (
	// SYS_PROC_INFO syscall 编号（macOS，amd64/arm64 通用）
	sysProcInfo = 336

	// proc_info 调用类型（第一个参数）
	procInfoCallPidInfo   = 2 // PROC_INFO_CALL_PIDINFO
	procInfoCallPidFdInfo = 3 // PROC_INFO_CALL_PIDFDINFO

	// PIDINFO flavor（第三个参数，当 call=PIDINFO 时）
	procPidListFDs = 1 // PROC_PIDLISTFDS

	// PIDFDINFO flavor（第三个参数，当 call=PIDFDINFO 时）
	procPidFdSocketInfo = 3 // PROC_PIDFDSOCKETINFO

	// FD 类型
	proxFdTypeSocket = 2 // PROX_FDTYPE_SOCKET

	// 地址族
	afINET  = 2  // AF_INET
	afINET6 = 30 // AF_INET6

	// 协议类型
	ipprotoTCP = 6  // IPPROTO_TCP
	ipprotoUDP = 17 // IPPROTO_UDP

	// Socket 类型
	sockStream = 1 // SOCK_STREAM (TCP)
	sockDgram  = 2 // SOCK_DGRAM  (UDP)
)

// ========== proc_fdinfo 结构体 (8 bytes) ==========

type procFdInfo struct {
	FD     int32
	FDType uint32
}

const procFdInfoSize = 8

// ========== socket_fdinfo buffer 内偏移 ==========
// 基于 XNU bsd/sys/proc_info.h，64-bit Darwin，macOS 10.7+ 稳定
//
// struct socket_fdinfo {
//     struct proc_fileinfo pfi;      // 16 bytes  (offset 0)
//     struct socket_info   psi;      // 360 bytes (offset 16)
// };
//
// struct socket_info 内关键字段偏移（相对于 socket_info 起始）：
//     vinfo_stat:    ~144 bytes
//     soi_so:        uint64 at 144
//     soi_pcb:       uint64 at 152
//     soi_type:      int32  at 160
//     soi_protocol:  int32  at 164
//     soi_family:    int32  at 168
//     soi_options:   int16  at 172
//     soi_linger:    int16  at 174
//     soi_state:     int16  at 176
//     ...padding to 192
//     soi_proto:     union  at 192

// 以下偏移基于 XNU bsd/sys/proc_info.h 分析。
// vinfo_stat 大小在不同 macOS 版本间可能不同（128 或 144 字节），
// 导致后续所有偏移漂移。parseSocketBuf 中有运行时校验：
// 如果提取的 family 不是 AF_INET/AF_INET6，会尝试备选偏移。
//
// 已知备选方案：
//   vinfo_stat=128 → offSoiType=16+144=160 → 以下为 "alt" 偏移
//   vinfo_stat=144 → offSoiType=16+160=176 → 以下为 "primary" 偏移
const (
	offPfi       = 0
	offSoi       = 16
	offSoiType   = offSoi + 160 // primary: vinfo_stat=144
	offSoiProto  = offSoi + 164
	offSoiFamily = offSoi + 168

	// soi_proto union 起始偏移
	offProtoUnion = offSoi + 192

	// in_sockinfo 内部偏移（相对于 proto union 起始）
	// struct in_sockinfo {
	//     int insi_fport;     // 0: foreign port (网络字节序存于 int32 低 16 位)
	//     int insi_lport;     // 4: local port
	//     uint64 insi_gencnt; // 8
	//     uint32 insi_flags;  // 16
	//     uint32 insi_flow;   // 20
	//     uint8  insi_vflag;  // 24: INI_IPV4=0x1, INI_IPV6=0x2
	//     uint8  insi_ip_ttl; // 25
	//     [2]pad              // 26-27
	//     uint32 insi_faddr[4]; // 28: foreign addr (in6_addr, 16 bytes)
	//     uint32 insi_laddr[4]; // 44: local addr (in6_addr, 16 bytes)
	//     uint8  insi_v4faddr[4]; // 60: IPv4 foreign addr
	//     uint8  insi_v4laddr[4]; // 64: IPv4 local addr
	// };
	offInsiFport  = offProtoUnion + 0
	offInsiLport  = offProtoUnion + 4
	offInsiVflag  = offProtoUnion + 24
	offInsiFaddr6 = offProtoUnion + 28 // 16 bytes (IPv6)
	offInsiLaddr6 = offProtoUnion + 44 // 16 bytes (IPv6)
	offInsiV4Fa   = offProtoUnion + 60 // 4 bytes (IPv4)
	offInsiV4La   = offProtoUnion + 64 // 4 bytes (IPv4)

	// TCP state 偏移: in_sockinfo 大小 ~72 字节 (含 padding)
	// struct tcp_sockinfo {
	//     struct in_sockinfo tcpsi_ini; // 72 bytes
	//     int tcpsi_state;             // tcp_fsm.h 值
	//     ...
	// };
	offTcpState = offProtoUnion + 72

	// 最小需要的 buffer 大小
	minSocketFdInfoBuf = offTcpState + 4 // 至少能读到 TCP state
	socketFdInfoBufSize = 376            // sizeof(struct socket_fdinfo) 标准大小
)

// ========== TCP state 映射 ==========
// macOS TCP state 值来自 XNU netinet/tcp_fsm.h
// 注意：与 Linux 的编号不同！

var macTCPStateNames = map[int32]string{
	0:  "CLOSED",
	1:  "LISTEN",
	2:  "SYN_SENT",
	3:  "SYN_RECEIVED",
	4:  "ESTABLISHED",
	5:  "CLOSE_WAIT",
	6:  "FIN_WAIT_1",
	7:  "CLOSING",
	8:  "LAST_ACK",
	9:  "FIN_WAIT_2",
	10: "TIME_WAIT",
}

func tcpStateName(state int32) string {
	if name, ok := macTCPStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

// ========== 地址解析 ==========

// extractAddr 从 socket_fdinfo buffer 中提取 IP 地址和端口
// vflag: 1=IPv4, 2=IPv6
// 返回 (ip, port, family_string, error)
func extractAddr(buf []byte, portOff, v4Off, v6Off int, vflag uint8) (net.IP, uint16, string, error) {
	if len(buf) < v6Off+16 {
		return nil, 0, "", fmt.Errorf("buffer 过短")
	}

	// 端口：存储为 int32，实际端口在低 16 位，网络字节序（大端）
	portRaw := binary.LittleEndian.Uint32(buf[portOff:])
	port := uint16(portRaw & 0xFFFF)
	// 端口本身是网络字节序存在 int32 中，需要翻转
	port = (port >> 8) | (port << 8)

	if vflag&0x1 != 0 {
		// IPv4
		ip := net.IPv4(buf[v4Off], buf[v4Off+1], buf[v4Off+2], buf[v4Off+3])
		return ip, port, "ipv4", nil
	}
	if vflag&0x2 != 0 {
		// IPv6
		ip := make(net.IP, 16)
		copy(ip, buf[v6Off:v6Off+16])
		return ip, port, "ipv6", nil
	}
	return nil, 0, "", fmt.Errorf("未知 vflag: %d", vflag)
}
