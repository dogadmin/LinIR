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
	cfg        WatchConfig
	appCfg     *config.Config
	iocStore   *IOCStore
	collectors *collector.PlatformCollectors
	trigger    *TriggerPolicy
	enricher   *Enricher
	writer     *EventWriter
	yaraScanner *yara.Scanner
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
		cfg:         cfg,
		appCfg:      appCfg,
		iocStore:    store,
		collectors:  collectors,
		trigger:     trigger,
		enricher:    enricher,
		writer:      writer,
		yaraScanner: yaraScanner,
	}, nil
}

// Run 启动监控主循环
func (e *Engine) Run(ctx context.Context) error {
	fmt.Printf("LinIR IOC 监控已启动 (间隔=%s", e.cfg.Interval)
	if e.cfg.Duration > 0 {
		fmt.Printf(", 时长=%s", e.cfg.Duration)
	}
	fmt.Println(")")
	fmt.Println("按 Ctrl+C 停止监控")
	fmt.Println()

	// 设置超时
	if e.cfg.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.Duration)
		defer cancel()
	}

	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()

	// 立即执行第一次
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

// scan 执行一次扫描周期
func (e *Engine) scan(ctx context.Context) {
	// 1. 获取连接快照
	conns, err := e.collectors.Network.CollectConnections(ctx)
	if err != nil {
		if e.cfg.Verbose {
			fmt.Printf("[WARN] 连接采集错误: %v\n", err)
		}
	}
	if len(conns) == 0 {
		return
	}

	// 2. IOC 比对
	hits := MatchConnections(conns, e.iocStore)
	if len(hits) == 0 {
		return
	}

	// 3. 对每个命中事件：去重 → 补采 → 输出
	for _, hit := range hits {
		select {
		case <-ctx.Done():
			return
		default:
		}

		decision := e.trigger.Evaluate(hit)
		if !decision.ShouldEnrich {
			if e.cfg.Verbose && decision.Deduped {
				// 去重的不打印
			} else if decision.RateLimited && e.cfg.Verbose {
				fmt.Printf("[RATE] %s\n", decision.Reason)
			}
			continue
		}

		// 补采
		evt := e.enricher.Enrich(ctx, hit)

		// YARA 补扫（engine 层处理，避免 enricher 循环导入）
		if e.yaraScanner != nil && evt.Process != nil && evt.Process.Exe != "" {
			yaraHits, err := e.yaraScanner.ScanFile(ctx, evt.Process.Exe)
			if err == nil {
				evt.YaraHits = yaraHits
			}
		}

		// 重新评分（YARA 结果可能改变分数）
		if len(evt.YaraHits) > 0 {
			for _, yh := range evt.YaraHits {
				evt.Score += 30
				evt.Evidence = append(evt.Evidence, model.Evidence{
					Domain: "yara", Rule: "yara_hit",
					Description: "YARA 规则命中: " + yh.Rule,
					Score: 30, Severity: "high",
				})
			}
			if evt.Score > 100 {
				evt.Score = 100
			}
			// 重算 severity
			switch {
			case evt.Score >= 80:
				evt.Severity = "critical"
			case evt.Score >= 60:
				evt.Severity = "high"
			case evt.Score >= 40:
				evt.Severity = "medium"
			}
			evt.Summary = buildEventSummary(&evt)
		}

		// 输出
		e.writer.WriteEvent(evt)
	}
}

// shutdown 优雅关闭
func (e *Engine) shutdown() error {
	fmt.Printf("\n监控结束。共产出 %d 个命中事件。\n", e.writer.EventCount())
	return nil
}
