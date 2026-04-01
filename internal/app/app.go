package app

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogadmin/LinIR/internal/collector"
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/correlate"
	"github.com/dogadmin/LinIR/internal/integrity"
	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/network"
	persistAnalyze "github.com/dogadmin/LinIR/internal/persistence"
	"github.com/dogadmin/LinIR/internal/preflight"
	"github.com/dogadmin/LinIR/internal/process"
	"github.com/dogadmin/LinIR/internal/report"
	"github.com/dogadmin/LinIR/internal/score"
	"github.com/dogadmin/LinIR/internal/selfcheck"
	"github.com/dogadmin/LinIR/internal/yara"
)

// App is the top-level orchestrator for LinIR.
type App struct {
	cfg        *config.Config
	collectors *collector.PlatformCollectors
	result     *model.CollectionResult
}

// New creates a new App with the given configuration.
func New(cfg *config.Config) (*App, error) {
	collectors, err := collector.NewPlatformCollectors()
	if err != nil {
		return nil, fmt.Errorf("initializing collectors: %w", err)
	}
	return &App{
		cfg:        cfg,
		collectors: collectors,
		result: &model.CollectionResult{
			Version:      cfg.Version,
			ToolName:     "linir",
			CollectionID: uuid.NewString(),
		},
	}, nil
}

// RunFull executes the full collection pipeline:
// selfcheck -> preflight -> collect all -> analyze -> correlate -> score -> output
func (a *App) RunFull(ctx context.Context) error {
	a.result.StartedAt = time.Now()
	defer a.finalize()

	a.runSelfCheck(ctx)
	if err := a.runPreflight(ctx); err != nil && !a.cfg.Force {
		return err
	}

	a.result.Capabilities = detectCapabilities()
	a.collectHost(ctx)
	a.collectProcesses(ctx)
	a.collectNetwork(ctx)
	a.collectPersistence(ctx)
	a.checkIntegrity(ctx)

	// Post-collection analysis
	process.Analyze(a.result.Processes)
	network.Analyze(a.result.Connections)
	persistAnalyze.Analyze(a.result.Persistence)

	// Cross-domain correlation
	correlate.Run(a.result)

	// YARA scan (if rules provided)
	if a.cfg.YaraRules != "" {
		a.runYaraScan(ctx)
	}

	// Scoring
	a.result.Score = score.Compute(a.result)

	return report.Generate(a.cfg, a.result)
}

// RunSingle runs a single collection domain.
func (a *App) RunSingle(ctx context.Context, domain string) error {
	a.result.StartedAt = time.Now()
	defer a.finalize()

	a.runSelfCheck(ctx)
	if err := a.runPreflight(ctx); err != nil && !a.cfg.Force {
		return err
	}
	a.result.Capabilities = detectCapabilities()

	switch domain {
	case "process":
		a.collectProcesses(ctx)
		process.Analyze(a.result.Processes)
	case "network":
		a.collectNetwork(ctx)
		network.Analyze(a.result.Connections)
	case "persistence":
		a.collectPersistence(ctx)
		persistAnalyze.Analyze(a.result.Persistence)
	case "integrity":
		a.checkIntegrity(ctx)
	default:
		return fmt.Errorf("unknown domain: %s", domain)
	}

	return report.Generate(a.cfg, a.result)
}

// RunPreflight runs only selfcheck and preflight.
func (a *App) RunPreflight(ctx context.Context) error {
	a.result.StartedAt = time.Now()
	defer a.finalize()

	a.runSelfCheck(ctx)
	if err := a.runPreflight(ctx); err != nil && !a.cfg.Force {
		return err
	}

	return report.Generate(a.cfg, a.result)
}

// RunYara runs YARA scanning only.
func (a *App) RunYara(ctx context.Context) error {
	a.result.StartedAt = time.Now()
	defer a.finalize()

	a.runSelfCheck(ctx)

	if a.cfg.YaraRules == "" {
		return fmt.Errorf("--rules 参数是 yara 子命令的必要参数")
	}

	// 如果指定了 --proc-linked，先采集进程和持久化信息以确定扫描目标
	if a.cfg.YaraProcLinked {
		if err := a.runPreflight(ctx); err != nil && !a.cfg.Force {
			return err
		}
		a.collectHost(ctx)
		a.collectProcesses(ctx)
		a.collectNetwork(ctx)
		a.collectPersistence(ctx)
	}

	a.runYaraScan(ctx)

	return report.Generate(a.cfg, a.result)
}

// Result returns the collection result.
func (a *App) Result() *model.CollectionResult {
	return a.result
}

func (a *App) finalize() {
	a.result.CompletedAt = time.Now()
	a.result.DurationMS = a.result.CompletedAt.Sub(a.result.StartedAt).Milliseconds()
}

func (a *App) runSelfCheck(ctx context.Context) {
	sc, err := selfcheck.Run(ctx)
	if err != nil {
		a.addError("selfcheck", err)
	}
	if sc != nil {
		a.result.SelfCheck = *sc
	}
}

func (a *App) runPreflight(ctx context.Context) error {
	pf, err := preflight.Run(ctx, a.cfg)
	if pf != nil {
		a.result.Preflight = *pf
	}
	if err != nil {
		a.addError("preflight", err)
		return fmt.Errorf("preflight failed (use --force to override): %w", err)
	}
	return nil
}

func (a *App) collectHost(ctx context.Context) {
	info, err := a.collectors.Host.CollectHostInfo(ctx)
	if err != nil {
		a.addError("host", err)
		return
	}
	if info != nil {
		info.CollectorVersion = a.cfg.Version
		info.CollectionTime = time.Now()
		a.result.Host = *info
	}
}

func (a *App) collectProcesses(ctx context.Context) {
	procs, err := a.collectors.Process.CollectProcesses(ctx)
	if err != nil {
		a.addError("process", err)
		return
	}
	a.result.Processes = procs
}

func (a *App) collectNetwork(ctx context.Context) {
	conns, err := a.collectors.Network.CollectConnections(ctx)
	if err != nil {
		a.addError("network", err)
		// 不 return——即使有错误（如 SIP 降级），仍保留已采集到的数据
	}
	if len(conns) > 0 {
		a.result.Connections = conns
	}
}

func (a *App) collectPersistence(ctx context.Context) {
	items, err := a.collectors.Persistence.CollectPersistence(ctx)
	if err != nil {
		a.addError("persistence", err)
		return
	}
	a.result.Persistence = items
}

func (a *App) checkIntegrity(ctx context.Context) {
	result, err := integrity.Check(ctx, a.result)
	if err != nil {
		a.addError("integrity", err)
		return
	}
	a.result.Integrity = result
}

func (a *App) runYaraScan(ctx context.Context) {
	if !yara.Available() {
		a.addError("yara", fmt.Errorf("YARA 支持未编译"))
		return
	}

	scanner, err := yara.NewScanner(a.cfg.YaraRules)
	if err != nil {
		a.addError("yara", fmt.Errorf("加载 YARA 规则: %w", err))
		return
	}

	if a.cfg.YaraTarget != "" {
		// 指定了扫描目标路径
		hits, err := scanner.ScanDir(ctx, a.cfg.YaraTarget)
		if err != nil {
			a.addError("yara", err)
		}
		a.result.YaraHits = append(a.result.YaraHits, hits...)
	}

	if a.cfg.YaraProcLinked || a.cfg.YaraTarget == "" {
		// 智能目标选择：基于已采集的进程/持久化/网络数据
		targets := yara.CollectHighRiskTargets(a.result)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				a.addError("yara", ctx.Err())
				return
			default:
			}
			hits, err := scanner.ScanFile(ctx, target.Path)
			if err != nil {
				continue
			}
			// 补充关联信息
			for i := range hits {
				hits[i].TargetType = target.TargetType
				hits[i].LinkedPID = target.LinkedPID
			}
			a.result.YaraHits = append(a.result.YaraHits, hits...)
		}
	}
}

func (a *App) addError(phase string, err error) {
	a.result.Errors = append(a.result.Errors, model.CollectionError{
		Phase:   phase,
		Message: err.Error(),
	})
}
