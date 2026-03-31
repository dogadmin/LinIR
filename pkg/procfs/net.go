//go:build linux

package procfs

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// NetEntry represents a parsed line from /proc/net/tcp or /proc/net/udp.
type NetEntry struct {
	LocalAddr  net.IP
	LocalPort  uint16
	RemoteAddr net.IP
	RemotePort uint16
	State      uint8
	UID        uint32
	Inode      uint64
}

// ReadNetTCP parses /proc/net/tcp.
func ReadNetTCP() ([]NetEntry, error) {
	return readNetFile(fmt.Sprintf("%s/net/tcp", ProcRoot), false)
}

// ReadNetTCP6 parses /proc/net/tcp6.
func ReadNetTCP6() ([]NetEntry, error) {
	return readNetFile(fmt.Sprintf("%s/net/tcp6", ProcRoot), true)
}

// ReadNetUDP parses /proc/net/udp.
func ReadNetUDP() ([]NetEntry, error) {
	return readNetFile(fmt.Sprintf("%s/net/udp", ProcRoot), false)
}

// ReadNetUDP6 parses /proc/net/udp6.
func ReadNetUDP6() ([]NetEntry, error) {
	return readNetFile(fmt.Sprintf("%s/net/udp6", ProcRoot), true)
}

// MapInodeToPID builds a map from socket inode to PID by scanning /proc/[pid]/fd/*.
func MapInodeToPID() (map[uint64]int, error) {
	pids, err := ListPIDs()
	if err != nil {
		return nil, err
	}

	m := make(map[uint64]int, 256)
	for _, pid := range pids {
		fdDir := fmt.Sprintf("%s/%d/fd", ProcRoot, pid)
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission denied or process exited
		}
		for _, entry := range entries {
			target, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, entry.Name()))
			if err != nil {
				continue
			}
			// Format: "socket:[12345]"
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inodeStr := target[8 : len(target)-1]
				if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
					m[inode] = pid
				}
			}
		}
	}

	return m, nil
}

func readNetFile(path string, isIPv6 bool) ([]NetEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("procfs: open %s: %w", path, err)
	}
	defer f.Close()

	var entries []NetEntry
	scanner := bufio.NewScanner(f)

	// Skip header line
	if scanner.Scan() {
		// discard header
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entry, err := parseNetLine(line, isIPv6)
		if err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func parseNetLine(line string, isIPv6 bool) (NetEntry, error) {
	// Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return NetEntry{}, fmt.Errorf("too few fields")
	}

	entry := NetEntry{}

	// Parse local address
	localAddr, localPort, err := parseAddrPort(fields[1], isIPv6)
	if err != nil {
		return NetEntry{}, err
	}
	entry.LocalAddr = localAddr
	entry.LocalPort = localPort

	// Parse remote address
	remoteAddr, remotePort, err := parseAddrPort(fields[2], isIPv6)
	if err != nil {
		return NetEntry{}, err
	}
	entry.RemoteAddr = remoteAddr
	entry.RemotePort = remotePort

	// State
	state, err := strconv.ParseUint(fields[3], 16, 8)
	if err != nil {
		return NetEntry{}, err
	}
	entry.State = uint8(state)

	// UID
	uid, err := strconv.ParseUint(fields[7], 10, 32)
	if err == nil {
		entry.UID = uint32(uid)
	}

	// Inode
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err == nil {
		entry.Inode = inode
	}

	return entry, nil
}

func parseAddrPort(s string, isIPv6 bool) (net.IP, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid addr:port: %s", s)
	}

	addrHex := parts[0]
	portHex := parts[1]

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, err
	}

	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, 0, err
	}

	var ip net.IP
	if isIPv6 {
		if len(addrBytes) != 16 {
			return nil, 0, fmt.Errorf("invalid ipv6 addr length: %d", len(addrBytes))
		}
		// /proc/net/tcp6 存储 IPv6 为 4 组 4 字节，每组按主机字节序排列。
		// 当前实现假设 little-endian (x86/amd64/arm64)。
		// 如果 LinIR 需要在 big-endian 架构 (s390x/mips) 上运行，此处需要调整。
		ip = make(net.IP, 16)
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				ip[i*4+j] = addrBytes[i*4+(3-j)]
			}
		}
	} else {
		if len(addrBytes) != 4 {
			return nil, 0, fmt.Errorf("invalid ipv4 addr length: %d", len(addrBytes))
		}
		// /proc/net/tcp stores IPv4 in host byte order (little-endian on x86)
		ip = net.IPv4(addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0])
	}

	return ip, uint16(port), nil
}

// ReadNetRaw parses /proc/net/raw.
func ReadNetRaw() ([]NetEntry, error) {
	return readNetFile(fmt.Sprintf("%s/net/raw", ProcRoot), false)
}

// ReadNetRaw6 parses /proc/net/raw6.
func ReadNetRaw6() ([]NetEntry, error) {
	return readNetFile(fmt.Sprintf("%s/net/raw6", ProcRoot), true)
}

// UnixSocketEntry 表示 /proc/net/unix 中的一条记录
type UnixSocketEntry struct {
	RefCount uint64
	Flags    uint32
	Type     uint32 // 1=STREAM, 2=DGRAM, 5=SEQPACKET
	State    uint8
	Inode    uint64
	Path     string
}

// ReadNetUnix 解析 /proc/net/unix
func ReadNetUnix() ([]UnixSocketEntry, error) {
	path := fmt.Sprintf("%s/net/unix", ProcRoot)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []UnixSocketEntry
	scanner := bufio.NewScanner(f)
	// 跳过标题行
	if scanner.Scan() {}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// 格式: Num RefCount Protocol Flags Type St Inode Path
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		entry := UnixSocketEntry{}
		entry.RefCount, _ = strconv.ParseUint(fields[1], 10, 64)
		flags, _ := strconv.ParseUint(fields[3], 10, 32)
		entry.Flags = uint32(flags)
		typ, _ := strconv.ParseUint(fields[4], 10, 32)
		entry.Type = uint32(typ)
		st, _ := strconv.ParseUint(fields[5], 16, 8)
		entry.State = uint8(st)
		entry.Inode, _ = strconv.ParseUint(fields[6], 10, 64)
		if len(fields) >= 8 {
			entry.Path = fields[7]
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

// TCPStateName returns a human-readable name for a TCP state number.
func TCPStateName(state uint8) string {
	names := map[uint8]string{
		0x01: "ESTABLISHED",
		0x02: "SYN_SENT",
		0x03: "SYN_RECV",
		0x04: "FIN_WAIT1",
		0x05: "FIN_WAIT2",
		0x06: "TIME_WAIT",
		0x07: "CLOSE",
		0x08: "CLOSE_WAIT",
		0x09: "LAST_ACK",
		0x0A: "LISTEN",
		0x0B: "CLOSING",
	}
	if name, ok := names[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%02X)", state)
}
