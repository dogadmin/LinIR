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
	"github.com/dogadmin/LinIR/internal/retained"
	"github.com/dogadmin/LinIR/internal/score"
	"github.com/dogadmin/LinIR/internal/selfcheck"
	"github.com/dogadmin/LinIR/internal/timeline"
	"github.com/dogadmin/LinIR/internal/triggerable"
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

// RunAnalysis executes the full three-state analysis pipeline:
// runtime collection + retained + triggerable + timeline.
func (a *App) RunAnalysis(ctx context.Context) error {
	a.result.StartedAt = time.Now()
	defer a.finalize()

	analysisResult := &model.AnalysisResult{
		Version:    a.cfg.Version,
		ToolName:   "linir",
		AnalysisID: uuid.NewString(),
		StartedAt:  a.result.StartedAt,
	}
	defer func() {
		analysisResult.CompletedAt = time.Now()
		analysisResult.DurationMS = analysisResult.CompletedAt.Sub(analysisResult.StartedAt).Milliseconds()
	}()

	// Phase 1: Standard runtime collection
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

	process.Analyze(a.result.Processes)
	network.Analyze(a.result.Connections)
	persistAnalyze.Analyze(a.result.Persistence)
	correlate.Run(a.result)

	if a.cfg.YaraRules != "" {
		a.runYaraScan(ctx)
	}
	a.result.Score = score.Compute(a.result)

	analysisResult.Host = a.result.Host
	analysisResult.Capabilities = a.result.Capabilities
	analysisResult.Runtime = a.result
	analysisResult.Confidence.Runtime = a.result.SelfCheck.CollectionConfidence
	if analysisResult.Confidence.Runtime == "" {
		analysisResult.Confidence.Runtime = "high"
	}

	// Phase 2: Retained state
	if a.cfg.WithRetained {
		rs, errs := a.collectRetained(ctx)
		analysisResult.Retained = rs
		if rs != nil {
			analysisResult.Confidence.Retained = rs.Confidence
		} else {
			analysisResult.Confidence.Retained = "unavailable"
		}
		for _, e := range errs {
			analysisResult.Errors = append(analysisResult.Errors, e)
		}
	} else {
		analysisResult.Confidence.Retained = "unavailable"
	}

	// Phase 3: Triggerable state
	if a.cfg.WithTriggerable {
		ts, errs := a.collectTriggerable(ctx)
		analysisResult.Triggerable = ts
		if ts != nil {
			analysisResult.Confidence.Triggerable = ts.Confidence
		} else {
			analysisResult.Confidence.Triggerable = "unavailable"
		}
		for _, e := range errs {
			analysisResult.Errors = append(analysisResult.Errors, e)
		}
	} else {
		analysisResult.Confidence.Triggerable = "unavailable"
	}

	// Phase 4: Timeline
	if a.cfg.WithTimeline {
		analysisResult.Timeline = timeline.Build(
			analysisResult.Runtime,
			analysisResult.Retained,
			analysisResult.Triggerable,
		)
	}

	// Phase 5: Extended scoring (retained + triggerable + cross-state)
	score.ComputeAnalysis(analysisResult)

	// Overall confidence = min of all available dimensions
	analysisResult.Confidence.Overall = minConfidence(
		analysisResult.Confidence.Runtime,
		analysisResult.Confidence.Retained,
		analysisResult.Confidence.Triggerable,
	)

	// Link back
	a.result.Analysis = analysisResult

	return report.GenerateAnalysis(a.cfg, analysisResult)
}

// RunRetained runs retained analysis with necessary runtime prerequisites.
func (a *App) RunRetained(ctx context.Context) error {
	a.result.StartedAt = time.Now()
	defer a.finalize()

	analysisResult := &model.AnalysisResult{
		Version:    a.cfg.Version,
		ToolName:   "linir",
		AnalysisID: uuid.NewString(),
		StartedAt:  a.result.StartedAt,
	}
	defer func() {
		analysisResult.CompletedAt = time.Now()
		analysisResult.DurationMS = analysisResult.CompletedAt.Sub(analysisResult.StartedAt).Milliseconds()
	}()

	a.runSelfCheck(ctx)
	if err := a.runPreflight(ctx); err != nil && !a.cfg.Force {
		return err
	}
	a.result.Capabilities = detectCapabilities()
	a.collectHost(ctx)
	a.collectProcesses(ctx)
	a.collectPersistence(ctx)

	analysisResult.Host = a.result.Host
	analysisResult.Capabilities = a.result.Capabilities
	analysisResult.Runtime = a.result
	analysisResult.Confidence.Runtime = "high"
	analysisResult.Confidence.Triggerable = "unavailable"

	rs, errs := a.collectRetained(ctx)
	analysisResult.Retained = rs
	if rs != nil {
		analysisResult.Confidence.Retained = rs.Confidence
	} else {
		analysisResult.Confidence.Retained = "unavailable"
	}
	for _, e := range errs {
		analysisResult.Errors = append(analysisResult.Errors, e)
	}

	analysisResult.Confidence.Overall = minConfidence(
		analysisResult.Confidence.Runtime,
		analysisResult.Confidence.Retained,
		analysisResult.Confidence.Triggerable,
	)

	a.result.Analysis = analysisResult
	return report.GenerateAnalysis(a.cfg, analysisResult)
}

// RunTriggerable runs triggerable analysis with necessary runtime prerequisites.
func (a *App) RunTriggerable(ctx context.Context) error {
	a.result.StartedAt = time.Now()
	defer a.finalize()

	analysisResult := &model.AnalysisResult{
		Version:    a.cfg.Version,
		ToolName:   "linir",
		AnalysisID: uuid.NewString(),
		StartedAt:  a.result.StartedAt,
	}
	defer func() {
		analysisResult.CompletedAt = time.Now()
		analysisResult.DurationMS = analysisResult.CompletedAt.Sub(analysisResult.StartedAt).Milliseconds()
	}()

	a.runSelfCheck(ctx)
	if err := a.runPreflight(ctx); err != nil && !a.cfg.Force {
		return err
	}
	a.result.Capabilities = detectCapabilities()
	a.collectHost(ctx)
	a.collectPersistence(ctx)

	analysisResult.Host = a.result.Host
	analysisResult.Capabilities = a.result.Capabilities
	analysisResult.Runtime = a.result
	analysisResult.Confidence.Runtime = "high"
	analysisResult.Confidence.Retained = "unavailable"

	ts, errs := a.collectTriggerable(ctx)
	analysisResult.Triggerable = ts
	if ts != nil {
		analysisResult.Confidence.Triggerable = ts.Confidence
	} else {
		analysisResult.Confidence.Triggerable = "unavailable"
	}
	for _, e := range errs {
		analysisResult.Errors = append(analysisResult.Errors, e)
	}

	analysisResult.Confidence.Overall = minConfidence(
		analysisResult.Confidence.Runtime,
		analysisResult.Confidence.Retained,
		analysisResult.Confidence.Triggerable,
	)

	a.result.Analysis = analysisResult
	return report.GenerateAnalysis(a.cfg, analysisResult)
}

// RunTimeline runs all three states and generates a unified timeline.
func (a *App) RunTimeline(ctx context.Context) error {
	a.cfg.WithRetained = true
	a.cfg.WithTriggerable = true
	a.cfg.WithTimeline = true
	return a.RunAnalysis(ctx)
}

func (a *App) collectRetained(ctx context.Context) (*model.RetainedState, []model.CollectionError) {
	c, err := retained.NewPlatformCollector()
	if err != nil {
		return nil, []model.CollectionError{{Phase: "retained", Message: err.Error()}}
	}
	return retained.Collect(ctx, c, a.cfg.RetainedWindow, a.result.Processes, a.result.Persistence)
}

func (a *App) collectTriggerable(ctx context.Context) (*model.TriggerableState, []model.CollectionError) {
	c, err := triggerable.NewPlatformCollector()
	if err != nil {
		return nil, []model.CollectionError{{Phase: "triggerable", Message: err.Error()}}
	}
	return triggerable.Collect(ctx, c)
}

func minConfidence(levels ...string) string {
	ranks := map[string]int{"high": 3, "medium": 2, "low": 1}
	min := -1 // -1 means no available dimension seen
	for _, l := range levels {
		if l == "unavailable" || l == "" {
			continue
		}
		r := ranks[l]
		if min < 0 || r < min {
			min = r
		}
	}
	switch min {
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "low" // all dimensions unavailable
	}
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
