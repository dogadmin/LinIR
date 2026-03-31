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

// collectSysctlConnections 通过 sysctl pcblist 采集全系统 TCP/UDP 连接。
//
// 这是 proc_pidfdinfo 的兜底方案。当 SIP 阻止按进程遍历 FD 时，
// sysctl 接口仍然可以返回全局连接视图（等价于 netstat -an 的数据源）。
//
// 限制：不包含 PID 信息，所有连接的 PID=0。
// 优势：不受 SIP 限制，可以看到所有连接。
func collectSysctlConnections(ctx context.Context) ([]model.ConnectionInfo, error) {
	var conns []model.ConnectionInfo

	// 按协议遍历所有 pcblist sysctl（含 IPv4 和 IPv6）
	pcbSources := []struct {
		sysctl string
		proto  string
	}{
		{"net.inet.tcp.pcblist", "tcp"},
		{"net.inet.udp.pcblist", "udp"},
		{"net.inet6.tcp6.pcblist", "tcp"},
		{"net.inet6.udp6.pcblist", "udp"},
	}

	for _, src := range pcbSources {
		select {
		case <-ctx.Done():
			return conns, ctx.Err()
		default:
		}
		raw, err := unix.SysctlRaw(src.sysctl)
		if err == nil && len(raw) > 0 {
			conns = append(conns, parsePcbList(raw, src.proto)...)
		}
	}

	if len(conns) == 0 {
		return nil, fmt.Errorf("sysctl pcblist 未返回任何连接")
	}

	return conns, nil
}

// parsePcbList 解析 sysctl net.inet.tcp/udp.pcblist 返回的二进制 blob。
//
// 格式：
//   [xinpgen header] [record 1] [record 2] ... [xinpgen footer]
//   每条记录开头 4 字节 = 记录长度 (little-endian uint32)
//   footer 的长度等于 header 的长度（通常 24 字节）
func parsePcbList(raw []byte, proto string) []model.ConnectionInfo {
	if len(raw) < 8 {
		return nil
	}

	// 读取 header 长度
	headerLen := int(binary.LittleEndian.Uint32(raw[0:4]))
	if headerLen < 8 || headerLen > len(raw) {
		return nil
	}

	var conns []model.ConnectionInfo
	pos := headerLen

	for pos+4 <= len(raw) {
		recLen := int(binary.LittleEndian.Uint32(raw[pos : pos+4]))
		if recLen < 24 {
			break // footer 或损坏数据
		}
		if pos+recLen > len(raw) {
			break
		}

		record := raw[pos : pos+recLen]
		conn := parseRecord(record, proto)
		if conn != nil {
			conns = append(conns, *conn)
		}

		pos += recLen
	}

	return conns
}

// parseRecord 从单条 pcblist 记录中提取连接信息。
// 使用 sockaddr 模式扫描而非硬编码偏移——更跨版本安全。
func parseRecord(record []byte, proto string) *model.ConnectionInfo {
	if len(record) < 80 {
		return nil
	}

	// 在记录中搜索 sockaddr_in (AF_INET) 或 sockaddr_in6 (AF_INET6) 模式
	addrs := findSockaddrs(record)
	if len(addrs) < 2 {
		return nil // 需要至少 local + remote 两个地址
	}

	local := addrs[0]
	remote := addrs[1]

	// 跳过全零地址的监听 socket（0.0.0.0:0 → 0.0.0.0:0）
	// 这些通常是未绑定的 socket
	if local.port == 0 && remote.port == 0 {
		return nil
	}

	conn := &model.ConnectionInfo{
		Proto:         proto,
		Family:        local.family,
		LocalAddress:  local.ip.String(),
		LocalPort:     local.port,
		RemoteAddress: remote.ip.String(),
		RemotePort:    remote.port,
		PID:           0, // sysctl 不提供 PID
		Source:        "sysctl_pcblist",
		Confidence:    "medium",
	}

	// TCP state: 尝试在记录末尾区域找 TCP state
	if proto == "tcp" {
		conn.State = extractTCPState(record)
	} else {
		conn.State = "STATELESS"
	}

	return conn
}

// sockaddrInfo 保存解析出的地址信息
type sockaddrInfo struct {
	ip     net.IP
	port   uint16
	family string
}

// findSockaddrs 在二进制记录中搜索 sockaddr_in/sockaddr_in6 模式。
//
// sockaddr_in 签名:  byte[0]=16(sa_len), byte[1]=2(AF_INET)
// sockaddr_in6 签名: byte[0]=28(sa_len), byte[1]=30(AF_INET6)
//
// 返回找到的所有地址（通常 2 个：local + remote）
func findSockaddrs(buf []byte) []sockaddrInfo {
	var result []sockaddrInfo

	for i := 0; i+16 <= len(buf); i++ {
		saLen := buf[i]
		saFamily := buf[i+1]

		if saLen == 16 && saFamily == 2 && i+16 <= len(buf) {
			// sockaddr_in: [1]len [1]family [2]port(BE) [4]addr [8]zero
			port := binary.BigEndian.Uint16(buf[i+2 : i+4])
			ip := net.IPv4(buf[i+4], buf[i+5], buf[i+6], buf[i+7])

			// 校验：后 8 字节应为零（sin_zero）
			allZero := true
			for _, b := range buf[i+8 : i+16] {
				if b != 0 {
					allZero = false
					break
				}
			}
			if !allZero {
				continue // 不是真正的 sockaddr_in
			}

			result = append(result, sockaddrInfo{ip: ip, port: port, family: "ipv4"})

			// 跳过这个 sockaddr 避免重复匹配
			i += 15
		} else if saLen == 28 && saFamily == 30 && i+28 <= len(buf) {
			// sockaddr_in6: [1]len [1]family [2]port(BE) [4]flowinfo [16]addr [4]scope
			port := binary.BigEndian.Uint16(buf[i+2 : i+4])
			ip := make(net.IP, 16)
			copy(ip, buf[i+8:i+24])

			result = append(result, sockaddrInfo{ip: ip, port: port, family: "ipv6"})
			i += 27
		}
	}

	return result
}

// extractTCPState 尝试从 TCP 记录中提取 TCP 状态。
// TCP state 通常在记录的后半部分。在 xtcpcb 结构中，
// tcpsi_state 是一个 int32，值范围 0-10（与 tcp_fsm.h 一致）。
// 我们从记录末尾往前搜索合理的状态值。
func extractTCPState(record []byte) string {
	// 策略：TCP state 值在 0-10 范围内，存储为 int32。
	// 在记录的后 64 字节中搜索第一个值在 [0,10] 范围的 int32，
	// 且前后字节不全为零（避免匹配到零填充区域）。
	searchStart := len(record) - 64
	if searchStart < len(record)/2 {
		searchStart = len(record) / 2
	}

	for i := searchStart; i+4 <= len(record); i += 4 {
		val := int32(binary.LittleEndian.Uint32(record[i : i+4]))
		if val >= 0 && val <= 10 {
			// 简单校验：非全零区域
			if i > 0 && record[i-1] == 0 && val > 0 {
				return tcpStateName(val)
			}
		}
	}

	// 回退：无法确定状态
	return "UNKNOWN"
}
