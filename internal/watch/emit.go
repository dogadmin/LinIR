package watch

// emitHit 非阻塞发送命中事件到 channel，满则丢弃并计数。
// 跨平台共享（Linux conntrack + macOS BPF 共用）。
func emitHit(ch chan<- HitEvent, hit HitEvent, metrics *WatchMetrics) {
	if metrics != nil {
		metrics.RawEventsTotal.Add(1)
		metrics.IOCMatchedTotal.Add(1)
	}
	select {
	case ch <- hit:
	default:
		if metrics != nil {
			metrics.EventChannelOverflow.Add(1)
		}
	}
}
