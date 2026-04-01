package watch

import (
	"context"
	"fmt"
	"time"

	"github.com/dogadmin/LinIR/internal/collector"
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
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
	if cfg.Verbose {
		store.DumpIOCs()
	}

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

	// 层 1: conntrack 事件驱动 (Linux) / BPF (macOS)
	if ConntrackAvailable() {
		return e.runConntrack(ctx)
	}

	// 层 2: /proc/net/nf_conntrack 轮询 (Linux only, RST 条目保留 10s)
	if NfConntrackAvailable() {
		return e.runNfConntrack(ctx)
	}

	// 层 3: /proc/net/tcp 轮询
	return e.runPolling(ctx)
}

// runConntrack 使用 conntrack 事件驱动监控（零遗漏，即使 RST 也能抓到）
func (e *Engine) runConntrack(ctx context.Context) error {
	fmt.Println("LinIR IOC 监控已启动")
	fmt.Println("[INFO] 监控模式: 事件驱动 (conntrack/BPF，零遗漏)")
	fmt.Println("按 Ctrl+C 停止监控")
	fmt.Println()

	monitor := NewConntrackMonitor(e.iocStore, e.cfg.Interface)

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
	fmt.Printf("LinIR IOC 监控已启动 (间隔=%s)\n", e.cfg.Interval)
	fmt.Println("[WARN] 监控模式: /proc/net/tcp 轮询 (可能遗漏 RST 短暂连接)")
	fmt.Println("[提示] sudo modprobe nf_conntrack → 可升级到 nf_conntrack 模式 (RST 保留 10s)")
	fmt.Println("[提示] sudo + CAP_NET_ADMIN → 可启用事件驱动模式 (零遗漏)")
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

// runNfConntrack 层 2：读 /proc/net/nf_conntrack（RST 条目保留 10s）+ /proc/net/tcp（PID 关联）
func (e *Engine) runNfConntrack(ctx context.Context) error {
	fmt.Printf("LinIR IOC 监控已启动 (间隔=%s)\n", e.cfg.Interval)
	fmt.Println("[INFO] 监控模式: nf_conntrack 轮询 (RST 连接可检测，条目保留 ~10s)")
	fmt.Println("[提示] sudo + CAP_NET_ADMIN → 可升级到事件驱动模式 (零遗漏)")
	fmt.Println("按 Ctrl+C 停止监控")
	fmt.Println()

	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()

	e.scanNfConntrack(ctx, true)

	for {
		select {
		case <-ctx.Done():
			return e.shutdown()
		case <-ticker.C:
			e.scanNfConntrack(ctx, false)
		}
	}
}

func (e *Engine) scanNfConntrack(ctx context.Context, isFirst bool) {
	e.scanCount++

	// 混合扫描：nf_conntrack + /proc/net/tcp
	nfConns, nfErr := ReadNfConntrackConns()
	if nfErr != nil && e.cfg.Verbose {
		fmt.Printf("[WARN] nf_conntrack 读取错误: %v\n", nfErr)
	}

	regularConns, _ := e.collectors.Network.CollectConnections(ctx)
	conns := mergeNfAndTcp(nfConns, regularConns)

	if isFirst {
		fmt.Printf("[INFO] 首次扫描: nf_conntrack=%d 条, /proc/net/tcp=%d 条, 合并=%d 条\n",
			len(nfConns), len(regularConns), len(conns))
		if len(conns) == 0 {
			fmt.Println("[WARN] 未采集到任何连接，请检查是否以 root/sudo 运行")
		}
	}

	if time.Since(e.lastStatusAt) >= 30*time.Second {
		fmt.Printf("[INFO] 扫描周期 #%d: nf=%d tcp=%d 合并=%d\n",
			e.scanCount, len(nfConns), len(regularConns), len(conns))
		e.lastStatusAt = time.Now()
	}

	if len(conns) == 0 {
		return
	}

	// 5. IOC 匹配
	hits := MatchConnections(conns, e.iocStore)
	if len(hits) == 0 {
		return
	}

	// 6. 补采 + YARA + 输出
	cache := e.enricher.CollectCache(ctx)
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
}

func connKeyForMerge(c model.ConnectionInfo) string {
	return fmt.Sprintf("%s:%s:%d:%s:%d", c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort)
}

// mergeNfAndTcp 合并 nf_conntrack 和 /proc/net/tcp 的连接。
// nf_conntrack 提供完整性（RST 条目保留 10s），/proc/net/tcp 提供 PID。
func mergeNfAndTcp(nfConns, tcpConns []model.ConnectionInfo) []model.ConnectionInfo {
	pidMap := make(map[string]int, len(tcpConns))
	for _, c := range tcpConns {
		if c.PID > 0 {
			pidMap[connKeyForMerge(c)] = c.PID
		}
	}

	seen := make(map[string]struct{})
	var merged []model.ConnectionInfo

	for i := range nfConns {
		key := connKeyForMerge(nfConns[i])
		seen[key] = struct{}{}
		if pid, ok := pidMap[key]; ok {
			nfConns[i].PID = pid
		}
		merged = append(merged, nfConns[i])
	}

	for _, rc := range tcpConns {
		if rc.Proto == "unix" {
			continue
		}
		if _, exists := seen[connKeyForMerge(rc)]; !exists {
			merged = append(merged, rc)
		}
	}
	return merged
}

// CollectWithNfConntrack 读 nf_conntrack + /proc/net/tcp 合并，供 GUI watch 使用
func CollectWithNfConntrack(ctx context.Context, collectors *collector.PlatformCollectors) ([]model.ConnectionInfo, error) {
	nfConns, nfErr := ReadNfConntrackConns()
	tcpConns, _ := collectors.Network.CollectConnections(ctx)
	return mergeNfAndTcp(nfConns, tcpConns), nfErr
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

	// DEBUG: 每次扫描都打印关键诊断信息
	if e.cfg.Verbose && connCount > 0 {
		// 打印前 3 个非 unix 连接的远端 IP，帮助排查格式匹配问题
		samples := 0
		for _, c := range conns {
			if c.Proto == "unix" || c.RemoteAddress == "" {
				continue
			}
			if samples < 3 {
				fmt.Printf("[DEBUG] 连接样本: %s %s:%d → %s:%d (PID=%d)\n",
					c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort, c.PID)
				samples++
			}
		}
	}

	if connCount == 0 {
		if e.cfg.Verbose {
			fmt.Printf("[WARN] 周期 #%d: 未采集到任何连接\n", e.scanCount)
		}
		return
	}

	// 2. IOC 比对
	hits := MatchConnections(conns, e.iocStore)
	if e.cfg.Verbose {
		fmt.Printf("[DEBUG] 周期 #%d: %d 条连接, %d 条 IOC 命中\n", e.scanCount, connCount, len(hits))
	}
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
