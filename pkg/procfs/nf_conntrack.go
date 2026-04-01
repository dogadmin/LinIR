//go:build linux

package procfs

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// NfConntrackEntry 表示 /proc/net/nf_conntrack 中的一条记录。
// nf_conntrack 相比 /proc/net/tcp 的优势：RST 后条目保留 ~10 秒，不会瞬间消失。
type NfConntrackEntry struct {
	L3Proto  string // "ipv4" or "ipv6"
	L4Proto  string // "tcp", "udp"
	ProtoNum uint8  // 6=TCP, 17=UDP
	State    string // "ESTABLISHED", "SYN_SENT", "CLOSE", "TIME_WAIT", etc.
	SrcAddr  net.IP
	DstAddr  net.IP
	SrcPort  uint16
	DstPort  uint16
}

// NfConntrackAvailable 检查 /proc/net/nf_conntrack 是否存在且可读
func NfConntrackAvailable() bool {
	f, err := os.Open(nfConntrackPath())
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func nfConntrackPath() string {
	path := fmt.Sprintf("%s/net/nf_conntrack", ProcRoot)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	// 2.6.14 以下内核使用旧路径
	return fmt.Sprintf("%s/net/ip_conntrack", ProcRoot)
}

// ReadNfConntrack 解析 /proc/net/nf_conntrack，返回所有 TCP/UDP 条目。
//
// 文件每行格式（空格分隔，字段数量和顺序可能因内核版本略有差异）：
//   ipv4     2 tcp      6 117 SYN_SENT src=192.168.1.2 dst=8.8.8.8 sport=54321 dport=80 ...
//   ipv4     2 udp      17 30 src=192.168.1.2 dst=8.8.4.4 sport=12345 dport=53 ...
//
// 注意：UDP 没有状态字段，第 5 个 field 直接是 TTL 后跟 key=value。
// TCP 有状态字段（SYN_SENT, ESTABLISHED, CLOSE 等）在 TTL 之后。
func ReadNfConntrack() ([]NfConntrackEntry, error) {
	f, err := os.Open(nfConntrackPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []NfConntrackEntry
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		entry, ok := parseNfConntrackLine(scanner.Text())
		if ok {
			entries = append(entries, entry)
		}
	}

	return entries, scanner.Err()
}

// parseNfConntrackLine 解析一行 nf_conntrack 记录。
// 只处理 TCP (proto 6) 和 UDP (proto 17)，其他协议跳过。
// 只提取原始方向（第一组 src/dst/sport/dport），忽略 reply 方向。
func parseNfConntrackLine(line string) (NfConntrackEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return NfConntrackEntry{}, false
	}

	entry := NfConntrackEntry{}
	entry.L3Proto = fields[0] // "ipv4" or "ipv6"

	// 协议号在 field[3]
	protoNum, err := strconv.ParseUint(fields[3], 10, 8)
	if err != nil {
		return NfConntrackEntry{}, false
	}
	entry.ProtoNum = uint8(protoNum)

	switch entry.ProtoNum {
	case 6:
		entry.L4Proto = "tcp"
	case 17:
		entry.L4Proto = "udp"
	default:
		return NfConntrackEntry{}, false // 跳过 ICMP 等
	}

	// 扫描 key=value 对提取地址和端口（只取第一组 = 原始方向）
	gotSrc, gotDst, gotSport, gotDport := false, false, false, false

	for _, f := range fields[4:] {
		// TCP 状态: 不含 '=' 且全大写（如 ESTABLISHED, SYN_SENT, CLOSE）
		if !strings.Contains(f, "=") && entry.L4Proto == "tcp" && entry.State == "" {
			// TTL 是纯数字，跳过
			if _, err := strconv.Atoi(f); err != nil {
				entry.State = f
			}
			continue
		}

		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]

		switch key {
		case "src":
			if !gotSrc {
				entry.SrcAddr = net.ParseIP(val)
				gotSrc = true
			}
		case "dst":
			if !gotDst {
				entry.DstAddr = net.ParseIP(val)
				gotDst = true
			}
		case "sport":
			if !gotSport {
				if p, err := strconv.ParseUint(val, 10, 16); err == nil {
					entry.SrcPort = uint16(p)
					gotSport = true
				}
			}
		case "dport":
			if !gotDport {
				if p, err := strconv.ParseUint(val, 10, 16); err == nil {
					entry.DstPort = uint16(p)
					gotDport = true
				}
			}
		}

		// 只需要第一组，收齐就停
		if gotSrc && gotDst && gotSport && gotDport {
			break
		}
	}

	if entry.SrcAddr == nil || entry.DstAddr == nil {
		return NfConntrackEntry{}, false
	}

	if entry.L4Proto == "udp" {
		entry.State = "STATELESS"
	}

	return entry, true
}
