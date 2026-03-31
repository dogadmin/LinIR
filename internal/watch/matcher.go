package watch

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
