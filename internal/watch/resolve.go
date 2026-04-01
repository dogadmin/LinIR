package watch

import (
	"context"
	"time"

	"github.com/dogadmin/LinIR/internal/collector"
	"github.com/dogadmin/LinIR/internal/model"
)

const (
	pidResolveAttempts = 4
	pidRetryInterval   = 50 * time.Millisecond
	pendingTimeout     = 5 * time.Second
)

// ResolveHitPIDWithRetry 多次重试快速定向 PID 解析。
// macOS 全量扫描太慢，只尝试一次。返回 true 表示解析成功。
func ResolveHitPIDWithRetry(ctx context.Context, hit *HitEvent, collectors *collector.PlatformCollectors) bool {
	attempts := pidResolveAttempts
	// macOS ResolveConnectionPID 是全量扫描，不适合多次重试
	if hit.Connection.Source == "bpf_syn" || hit.Connection.Source == "bpf_udp" {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		ResolveHitPID(ctx, hit, collectors)
		if hit.Connection.PID > 0 {
			return true
		}
		if i < attempts-1 {
			time.Sleep(pidRetryInterval)
		}
	}
	return false
}

// ResolvePendingHits 用轮询连接数据解析 pending 的 PID=0 事件（完整 5 元组匹配）。
// 返回未解析的 remaining 切片。resolved/expired 通过回调处理。
func ResolvePendingHits(
	pending []HitEvent,
	conns []model.ConnectionInfo,
	onResolved func(HitEvent),
	onExpired func(HitEvent),
) []HitEvent {
	if len(pending) == 0 {
		return nil
	}
	connIndex := make(map[string]*model.ConnectionInfo, len(conns))
	for i := range conns {
		if conns[i].PID > 0 {
			connIndex[ConnKey(conns[i])] = &conns[i]
		}
	}
	var remaining []HitEvent
	for _, ph := range pending {
		if c, ok := connIndex[ConnKey(ph.Connection)]; ok {
			ph.Connection.PID = c.PID
			ph.Connection.ProcessName = c.ProcessName
			onResolved(ph)
		} else if time.Since(ph.Timestamp) >= pendingTimeout {
			onExpired(ph)
		} else {
			remaining = append(remaining, ph)
		}
	}
	return remaining
}
