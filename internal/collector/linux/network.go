//go:build linux

package linux

import (
	"context"
	"fmt"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/procfs"
)

// NetworkCollector 通过直接解析 /proc/net/ 下的文件采集网络连接。
// 严禁调用 netstat、ss、lsof 或任何外部命令。
//
// 数据源：
//   /proc/net/tcp   — IPv4 TCP 连接
//   /proc/net/tcp6  — IPv6 TCP 连接
//   /proc/net/udp   — IPv4 UDP 套接字
//   /proc/net/udp6  — IPv6 UDP 套接字
//   /proc/net/raw   — IPv4 Raw 套接字
//   /proc/net/raw6  — IPv6 Raw 套接字
//   /proc/net/unix  — Unix 域套接字
//
// PID 关联：
//   /proc/net/* 只提供 socket inode，不直接给出 PID。
//   需要遍历所有 /proc/<pid>/fd/* 寻找 socket:[inode] 符号链接来建立
//   inode → PID 映射。这是 O(进程数 × fd数) 的操作，但在用户态下
//   是获取这个映射的唯一可靠方法（不使用 netlink）。
//
// 为什么不用 netstat/ss：
//   ss 底层走 netlink，但 ss 命令本身可被替换。
//   netstat 依赖 /proc 解析（和我们做的一样），但输出格式化过程可被篡改。
//   直接读 /proc/net/* 比调用命令更可信。
type NetworkCollector struct {
	procRoot string
}

func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{procRoot: "/proc"}
}

func (c *NetworkCollector) CollectConnections(ctx context.Context) ([]model.ConnectionInfo, error) {
	procfs.ProcRoot = c.procRoot

	// 1. 先构建 inode → PID 映射（最耗时的步骤）
	inodePID, err := procfs.MapInodeToPID()
	if err != nil {
		// 映射失败不致命，只是无法关联 PID
		inodePID = make(map[uint64]int)
	}

	var conns []model.ConnectionInfo

	// 2. 采集 TCP IPv4
	select {
	case <-ctx.Done():
		return conns, ctx.Err()
	default:
	}
	tcpEntries, err := procfs.ReadNetTCP()
	if err != nil {
		return nil, fmt.Errorf("读取 /proc/net/tcp 失败: %w", err)
	}
	for _, e := range tcpEntries {
		conns = append(conns, netEntryToConn(e, "tcp", "ipv4", inodePID))
	}

	// 3. 采集 TCP IPv6
	tcp6Entries, _ := procfs.ReadNetTCP6()
	for _, e := range tcp6Entries {
		conns = append(conns, netEntryToConn(e, "tcp", "ipv6", inodePID))
	}

	// 4. 采集 UDP IPv4
	udpEntries, _ := procfs.ReadNetUDP()
	for _, e := range udpEntries {
		conns = append(conns, netEntryToConn(e, "udp", "ipv4", inodePID))
	}

	// 5. 采集 UDP IPv6
	udp6Entries, _ := procfs.ReadNetUDP6()
	for _, e := range udp6Entries {
		conns = append(conns, netEntryToConn(e, "udp", "ipv6", inodePID))
	}

	// 6. 采集 Raw 套接字
	rawEntries, _ := procfs.ReadNetRaw()
	for _, e := range rawEntries {
		conns = append(conns, netEntryToConn(e, "raw", "ipv4", inodePID))
	}
	raw6Entries, _ := procfs.ReadNetRaw6()
	for _, e := range raw6Entries {
		conns = append(conns, netEntryToConn(e, "raw", "ipv6", inodePID))
	}

	// 7. 采集 Unix 域套接字
	unixEntries, _ := procfs.ReadNetUnix()
	for _, e := range unixEntries {
		conns = append(conns, unixEntryToConn(e, inodePID))
	}

	return conns, nil
}

// netEntryToConn 将 procfs.NetEntry 转换为 model.ConnectionInfo
func netEntryToConn(e procfs.NetEntry, proto, family string, inodePID map[uint64]int) model.ConnectionInfo {
	// /proc/net/tcp6 中的 IPv4-mapped IPv6 (::ffff:x.x.x.x) 归一化为 IPv4
	if family == "ipv6" {
		if e.LocalAddr.To4() != nil || e.RemoteAddr.To4() != nil {
			family = "ipv4"
		}
	}

	conn := model.ConnectionInfo{
		Proto:         proto,
		Family:        family,
		LocalAddress:  e.LocalAddr.String(),
		LocalPort:     e.LocalPort,
		RemoteAddress: e.RemoteAddr.String(),
		RemotePort:    e.RemotePort,
		SocketInode:   e.Inode,
		Source:        "procfs",
		Confidence:    "high",
	}

	// TCP state 转换为可读名称
	if proto == "tcp" {
		conn.State = procfs.TCPStateName(e.State)
	} else {
		// UDP 没有状态机，但 /proc/net/udp 的 state 字段也有值
		if e.State == 0x07 {
			conn.State = "CLOSE"
		} else if e.State == 0x01 {
			conn.State = "ESTABLISHED"
		} else {
			conn.State = fmt.Sprintf("0x%02X", e.State)
		}
	}

	// 通过 inode 关联 PID
	if pid, ok := inodePID[e.Inode]; ok {
		conn.PID = pid
	} else if e.Inode != 0 {
		// inode 存在但找不到对应进程——可能是进程已退出或被隐藏
		conn.Confidence = "medium"
	}

	return conn
}

// unixEntryToConn 将 procfs.UnixSocketEntry 转换为 model.ConnectionInfo
func unixEntryToConn(e procfs.UnixSocketEntry, inodePID map[uint64]int) model.ConnectionInfo {
	conn := model.ConnectionInfo{
		Proto:        "unix",
		Family:       "unix",
		LocalAddress: e.Path,
		SocketInode:  e.Inode,
		Source:       "procfs",
		Confidence:   "high",
	}

	// Unix socket 类型
	switch e.Type {
	case 1:
		conn.State = "STREAM"
	case 2:
		conn.State = "DGRAM"
	case 5:
		conn.State = "SEQPACKET"
	default:
		conn.State = fmt.Sprintf("TYPE_%d", e.Type)
	}

	// 通过 inode 关联 PID
	if pid, ok := inodePID[e.Inode]; ok {
		conn.PID = pid
	}

	return conn
}
