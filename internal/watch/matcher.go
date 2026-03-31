package watch

// 设计说明：
//
// ICMP (ping): ping 使用 ICMP 原始套接字。Linux 的 /proc/net/raw 虽然记录了
// 原始套接字，但远端地址通常为 0.0.0.0，而非 ping 的目标地址。ICMP 回显请求
// 的目标 IP 嵌入在数据包 payload 中，不作为 socket 级别的"远端地址"被跟踪。
// 这是操作系统层面的限制：ICMP 连接无法通过本匹配方式检测。
//
// 域名 IOC: 当前仅实现了 IP 匹配。域名 IOC 可以被加载和存储，但不会与连接
// 进行匹配，因为连接信息中只包含 IP 地址而非主机名。实现域名匹配需要反向
// DNS 查询（开销大、不可靠，且可能暴露给对手）或 DNS 流量嗅探（需要 pcap/BPF
// 权限）。域名 IOC 保留用于未来增强。

import (
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// MatchConnections 将连接快照与 IOC 列表比对，返回所有命中事件
func MatchConnections(conns []model.ConnectionInfo, store *IOCStore) []HitEvent {
	var hits []HitEvent
	now := time.Now()

	for _, conn := range conns {
		// 跳过 unix socket 和无效连接
		if conn.Proto == "unix" || (conn.RemoteAddress == "" && conn.LocalAddress == "") {
			continue
		}

		// 检查远端地址是否命中 IP IOC
		if ioc, ok := store.MatchIP(conn.RemoteAddress); ok {
			hits = append(hits, HitEvent{
				Timestamp:  now,
				IOC:        ioc,
				MatchType:  "direct_ip",
				Connection: conn,
			})
			continue // 一条连接只报一次
		}

		// 检查本地地址（反向连接场景：攻击者连进来）
		if ioc, ok := store.MatchIP(conn.LocalAddress); ok {
			hits = append(hits, HitEvent{
				Timestamp:  now,
				IOC:        ioc,
				MatchType:  "direct_ip",
				Connection: conn,
			})
		}
	}

	return hits
}
