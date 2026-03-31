package network

import (
	"github.com/dogadmin/LinIR/internal/model"
)

// Analyze 对采集后的网络连接进行二次分析，标记可疑连接。
func Analyze(conns []model.ConnectionInfo) {
	if len(conns) == 0 {
		return
	}

	for i := range conns {
		analyzeConnection(&conns[i])
	}
}

func analyzeConnection(c *model.ConnectionInfo) {
	if c.Proto == "unix" {
		return
	}

	// Raw socket
	if c.Proto == "raw" {
		addConnFlag(c, "raw_socket")
	}

	// 无归属进程的活跃连接
	if c.PID == 0 && c.SocketInode != 0 {
		if c.State == "ESTABLISHED" || c.State == "LISTEN" {
			addConnFlag(c, "orphan_active_connection")
		}
	}

	// LISTEN 在所有接口
	if c.State == "LISTEN" {
		if c.LocalAddress == "0.0.0.0" || c.LocalAddress == "::" {
			addConnFlag(c, "listen_all_interfaces")
		}
	}

	// 外连到已知可疑端口
	if c.State == "ESTABLISHED" && c.RemotePort > 0 {
		suspiciousPorts := map[uint16]string{
			4444:  "metasploit_default",
			5555:  "common_backdoor",
			6666:  "common_backdoor",
			6667:  "irc_c2",
			6668:  "irc_c2",
			6669:  "irc_c2",
			1234:  "common_backdoor",
			31337: "elite_backdoor",
		}
		if desc, ok := suspiciousPorts[c.RemotePort]; ok {
			addConnFlag(c, "suspicious_remote_port:"+desc)
		}
	}

	// 反弹 shell 特征：ESTABLISHED + 远程低端口 + 本地高端口
	if c.State == "ESTABLISHED" && c.RemotePort > 0 && c.RemotePort <= 1024 && c.LocalPort > 1024 {
		addConnFlag(c, "possible_reverse_connect")
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
