package network

import (
	"github.com/dogadmin/LinIR/internal/model"
)

// Analyze 对采集后的网络连接进行二次分析，标记可疑连接。
// 设计原则：只标记真正异常的连接，不标记正常服务器/客户端行为。
func Analyze(conns []model.ConnectionInfo) {
	for i := range conns {
		analyzeConnection(&conns[i])
	}
}

func analyzeConnection(c *model.ConnectionInfo) {
	if c.Proto == "unix" {
		return
	}

	// 无归属进程的活跃连接（有 inode 但找不到进程——可能被隐藏）
	if c.PID == 0 && c.SocketInode != 0 {
		if c.State == "ESTABLISHED" || c.State == "LISTEN" {
			addConnFlag(c, "orphan_active_connection")
		}
	}

	// 外连到高度可疑的 C2 端口（只保留最明确的）
	if c.State == "ESTABLISHED" && c.RemotePort > 0 {
		suspiciousPorts := map[uint16]string{
			4444:  "metasploit_default",
			31337: "elite_backdoor",
		}
		if desc, ok := suspiciousPorts[c.RemotePort]; ok {
			addConnFlag(c, "suspicious_remote_port:"+desc)
		}
	}
}

func addConnFlag(c *model.ConnectionInfo, flag string) {
	for _, f := range c.SuspiciousFlags {
		if f == flag {
			return
		}
	}
	c.SuspiciousFlags = append(c.SuspiciousFlags, flag)
}
