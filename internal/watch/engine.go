package watch

import (
	"context"
	"fmt"
	"time"

	"github.com/dogadmin/LinIR/internal/collector"
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/preflight"
	"github.com/dogadmin/LinIR/internal/selfcheck"
	"github.com/dogadmin/LinIR/internal/yara"
)

// Engine 是 IOC 在线监控的主引擎
type Engine struct {
	cfg          WatchConfig
	appCfg       *config.Config
	iocStore     *IOCStore
	collectors   *collector.PlatformCollectors
	trigger      *TriggerPolicy
	enricher     *Enricher
	writer       *EventWriter
	yaraScanner  *yara.Scanner
	scanCount    int
	lastStatusAt time.Time
}

// NewEngine 创建监控引擎
func NewEngine(cfg WatchConfig, appCfg *config.Config) (*Engine, error) {
	// 1. 加载 IOC
	store, err := LoadIOCFile(cfg.IOCFile)
	if err != nil {
		return nil, fmt.Errorf("加载 IOC: %w", err)
	}
	fmt.Printf("已加载 %d 条 IOC (%d IP, %d 域名)\n", store.Total(), store.IPCount(), store.DomainCount())

	// 2. 初始化平台 collector
	collectors, err := collector.NewPlatformCollectors()
	if err != nil {
		return nil, fmt.Errorf("初始化采集器: %w", err)
	}

	// 3. 加载白名单（可选）
	var wl *Whitelist
	if cfg.WhitelistFile != "" {
		wl, err = LoadWhitelist(cfg.WhitelistFile)
		if err != nil {
			return nil, fmt.Errorf("加载白名单: %w", err)
		}
	}

	// 4. 执行自检和预检
	sc, _ := selfcheck.Run(context.Background())
	pf, _ := preflight.Run(context.Background(), appCfg)

	// 5. 创建触发策略
	trigger := NewTriggerPolicy(cfg.DedupeWindow, cfg.MaxEvents, wl)

	// 6. 创建补采器
	enricher := NewEnricher(collectors, cfg.YaraRules, pf, sc)

	// 7. 创建输出器
	writer := NewEventWriter(cfg)

	// 8. 初始化 YARA（可选）
	var yaraScanner *yara.Scanner
	if cfg.YaraRules != "" && yara.Available() {
		yaraScanner, err = yara.NewScanner(cfg.YaraRules)
		if err != nil {
			fmt.Printf("YARA 规则加载失败: %v (继续运行但不扫描)\n", err)
		} else {
			fmt.Printf("已加载 %d 条 YARA 规则\n", yaraScanner.RuleCount())
		}
	}

	return &Engine{
		cfg:          cfg,
		appCfg:       appCfg,
		iocStore:     store,
		collectors:   collectors,
		trigger:      trigger,
		enricher:     enricher,
		writer:       writer,
		yaraScanner:  yaraScanner,
		lastStatusAt: time.Now(),
	}, nil
}

// Run 启动监控主循环
func (e *Engine) Run(ctx context.Context) error {
	// 设置超时
	if e.cfg.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.Duration)
		defer cancel()
	}

	// 尝试 conntrack 事件驱动模式（Linux，需要 nf_conntrack 模块）
	if ConntrackAvailable() {
		return e.runConntrack(ctx)
	}

	// 降级到轮询模式
	return e.runPolling(ctx)
}

// runConntrack 使用 conntrack 事件驱动监控（零遗漏，即使 RST 也能抓到）
func (e *Engine) runConntrack(ctx context.Context) error {
	fmt.Println("LinIR IOC 监控已启动 (模式=conntrack 事件驱动)")
	fmt.Println("按 Ctrl+C 停止监控")
	fmt.Println()

	monitor := NewConntrackMonitor(e.iocStore)

	// 后台启动 conntrack 监听
	ctxMon, cancelMon := context.WithCancel(ctx)
	defer cancelMon()

	errCh := make(chan error, 1)
	go func() {
		errCh <- monitor.Run(ctxMon)
	}()

	// 同时保留轮询作为补充（捕获已有连接，conntrack 只报新连接）
	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()

	// 首次轮询
	e.scan(ctx)
	fmt.Printf("[INFO] 首次扫描完成 (conntrack 模式，轮询作为补充)\n")

	for {
		select {
		case <-ctx.Done():
			cancelMon()
			return e.shutdown()
		case err := <-errCh:
			if err != nil {
				fmt.Printf("[WARN] conntrack 断开: %v，切换到轮询模式\n", err)
				return e.runPolling(ctx)
			}
			return e.shutdown()
		case hit := <-monitor.Events():
			e.handleHit(ctx, hit)
		case <-ticker.C:
			e.scan(ctx)
		}
	}
}

// runPolling 使用传统轮询模式
func (e *Engine) runPolling(ctx context.Context) error {
	fmt.Printf("LinIR IOC 监控已启动 (模式=轮询, 间隔=%s)\n", e.cfg.Interval)
	fmt.Println("[INFO] 事件驱动不可用，使用轮询模式 (可能遗漏短暂连接)")
	fmt.Println("[提示] Linux: modprobe nf_conntrack | macOS: 需要 root 权限")
	fmt.Println("按 Ctrl+C 停止监控")
	fmt.Println()

	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()

	// 首次扫描状态输出
	conns, err := e.collectors.Network.CollectConnections(ctx)
	if err != nil {
		fmt.Printf("[WARN] 连接采集错误: %v\n", err)
	}
	fmt.Printf("[INFO] 首次扫描: 采集到 %d 条连接\n", len(conns))
	if len(conns) == 0 {
		fmt.Println("[WARN] 未采集到任何连接，请检查是否以 root/sudo 运行")
	}
	e.scan(ctx)

	for {
		select {
		case <-ctx.Done():
			return e.shutdown()
		case <-ticker.C:
			e.scan(ctx)
		}
	}
}

// handleHit 处理单个 conntrack 命中事件
func (e *Engine) handleHit(ctx context.Context, hit HitEvent) {
	decision := e.trigger.Evaluate(hit)
	if !decision.ShouldEnrich {
		return
	}

	cache := e.enricher.CollectCache(ctx)
	evt := e.enricher.Enrich(ctx, hit, cache)

	if e.yaraScanner != nil && evt.Process != nil && evt.Process.Exe != "" {
		yaraHits, scanErr := e.yaraScanner.ScanFile(ctx, evt.Process.Exe)
		if scanErr == nil && len(yaraHits) > 0 {
			evt.YaraHits = yaraHits
			scoreEvent(&evt)
		}
	}

	e.writer.WriteEvent(evt)
}

// scan 执行一次扫描周期
func (e *Engine) scan(ctx context.Context) {
	e.scanCount++

	// 1. 获取连接快照
	conns, err := e.collectors.Network.CollectConnections(ctx)
	if err != nil && e.cfg.Verbose {
		fmt.Printf("[WARN] 连接采集错误: %v\n", err)
	}

	connCount := len(conns)

	// 周期性状态日志（每 30 秒或 verbose 模式每次）
	if time.Since(e.lastStatusAt) >= 30*time.Second {
		fmt.Printf("[INFO] 扫描周期 #%d: 采集到 %d 条连接\n", e.scanCount, connCount)
		e.lastStatusAt = time.Now()
	}

	if connCount == 0 {
		if e.cfg.Verbose {
			fmt.Printf("[WARN] 周期 #%d: 未采集到任何连接\n", e.scanCount)
		}
		return
	}

	// 2. IOC 比对
	hits := MatchConnections(conns, e.iocStore)
	if len(hits) == 0 {
		return
	}

	// 3. 预采集上下文（每周期一次，所有命中共享）
	cache := e.enricher.CollectCache(ctx)

	// 4. 对每个命中事件：去重 → 补采 → YARA → 输出
	for _, hit := range hits {
		select {
		case <-ctx.Done():
			return
		default:
		}

		decision := e.trigger.Evaluate(hit)
		if !decision.ShouldEnrich {
			continue
		}

		// 补采（使用 cache，不重复采集）
		evt := e.enricher.Enrich(ctx, hit, cache)

		// YARA 补扫
		if e.yaraScanner != nil && evt.Process != nil && evt.Process.Exe != "" {
			yaraHits, scanErr := e.yaraScanner.ScanFile(ctx, evt.Process.Exe)
			if scanErr == nil && len(yaraHits) > 0 {
				evt.YaraHits = yaraHits
				// 重新评分（YARA 结果改变分数）
				scoreEvent(&evt)
			}
		}

		e.writer.WriteEvent(evt)
	}
}

// shutdown 优雅关闭
func (e *Engine) shutdown() error {
	fmt.Printf("\n监控结束。共产出 %d 个命中事件。\n", e.writer.EventCount())
	return nil
}
