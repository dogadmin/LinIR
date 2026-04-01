package watch

import (
	"fmt"
	"sync"
	"time"
)

// TriggerPolicy 管理去重、频控和白名单策略
type TriggerPolicy struct {
	dedupeWindow time.Duration
	maxPerMinute int
	whitelist    *Whitelist
	seen         map[string]time.Time // dedup key → last seen time
	minuteCount  int
	minuteStart  time.Time
	mu           sync.Mutex
}

// NewTriggerPolicy 创建触发策略
func NewTriggerPolicy(dedupeWindow time.Duration, maxPerMinute int, wl *Whitelist) *TriggerPolicy {
	return &TriggerPolicy{
		dedupeWindow: dedupeWindow,
		maxPerMinute: maxPerMinute,
		whitelist:    wl,
		seen:         make(map[string]time.Time),
		minuteStart:  time.Now(),
	}
}

// Evaluate 判断命中事件是否应触发补采
func (tp *TriggerPolicy) Evaluate(hit HitEvent) TriggerDecision {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	// 1. 白名单检查
	if tp.whitelist != nil {
		if tp.whitelist.ShouldSuppress(hit) {
			return TriggerDecision{
				ShouldEnrich: false,
				Deduped:      false,
				RateLimited:  false,
				Reason:       "whitelist_suppressed",
			}
		}
	}

	// 2. 去重检查
	key := dedupeKey(hit)
	if lastSeen, ok := tp.seen[key]; ok {
		if time.Since(lastSeen) < tp.dedupeWindow {
			return TriggerDecision{
				ShouldEnrich: false,
				Deduped:      true,
				Reason:       fmt.Sprintf("deduped (last seen %s ago)", time.Since(lastSeen).Truncate(time.Second)),
			}
		}
	}

	// 3. 频控检查
	if tp.maxPerMinute > 0 {
		if time.Since(tp.minuteStart) > time.Minute {
			tp.minuteCount = 0
			tp.minuteStart = time.Now()
		}
		if tp.minuteCount >= tp.maxPerMinute {
			return TriggerDecision{
				ShouldEnrich: false,
				RateLimited:  true,
				Reason:       fmt.Sprintf("rate limited (%d/min)", tp.maxPerMinute),
			}
		}
	}

	// 通过所有检查——允许触发
	if hit.Connection.PID > 0 {
		tp.seen[key] = time.Now()
	} else {
		// PID=0 用短窗口（5 秒）防刷屏，但不阻塞后续带 PID 的事件
		tp.seen[key] = time.Now().Add(-(tp.dedupeWindow - 5*time.Second))
	}
	tp.minuteCount++

	// 定期清理过期去重条目
	tp.cleanExpired()

	return TriggerDecision{ShouldEnrich: true}
}

// dedupeKey 生成去重键：IOC值 + 远端地址:端口
// 不含 PID 和本地端口，避免 BPF/conntrack 事件模式下同一 IOC 的不同连接重复报告
func dedupeKey(hit HitEvent) string {
	return fmt.Sprintf("%s:%s:%d",
		hit.IOC.Value,
		hit.Connection.RemoteAddress, hit.Connection.RemotePort)
}

func (tp *TriggerPolicy) cleanExpired() {
	now := time.Now()
	for k, t := range tp.seen {
		if now.Sub(t) > tp.dedupeWindow*2 {
			delete(tp.seen, k)
		}
	}
}
