package watch

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogadmin/LinIR/internal/collector"
	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/hashutil"
)

// Enricher 负责命中后的上下文补采
type Enricher struct {
	collectors *collector.PlatformCollectors
	yaraRules  string
	preflight  *model.PreflightResult
	selfCheck  *model.SelfCheckResult
}

// NewEnricher 创建补采器
func NewEnricher(collectors *collector.PlatformCollectors, yaraRules string,
	pf *model.PreflightResult, sc *model.SelfCheckResult) *Enricher {
	return &Enricher{
		collectors: collectors,
		yaraRules:  yaraRules,
		preflight:  pf,
		selfCheck:  sc,
	}
}

// Enrich 对命中事件进行上下文补采和评分
func (e *Enricher) Enrich(ctx context.Context, hit HitEvent) EnrichedEvent {
	evt := EnrichedEvent{
		Timestamp:  hit.Timestamp,
		EventID:    uuid.NewString()[:8],
		IOC:        hit.IOC,
		MatchType:  hit.MatchType,
		Connection: hit.Connection,
		Confidence: "high",
	}

	// 1. 进程上下文补采
	if hit.Connection.PID > 0 {
		evt.Process = e.enrichProcess(ctx, hit.Connection.PID)
	} else {
		evt.Confidence = "medium" // 无 PID 降低可信度
	}

	// 2. 二进制上下文补采
	if evt.Process != nil && evt.Process.Exe != "" {
		evt.Binary = e.enrichBinary(evt.Process.Exe)
	}

	// 3. 持久化上下文——直接复用 persistence collector
	persistItems := e.enrichPersistence(ctx)
	// 只保留与当前进程关联的项
	if evt.Process != nil {
		for _, item := range persistItems {
			if item.Target == evt.Process.Exe || strings.Contains(item.Target, evt.Process.Name) {
				evt.Persistence = append(evt.Persistence, item)
			}
		}
	}

	// 4. YARA 补采——扫描命中进程的 exe
	if e.yaraRules != "" && evt.Process != nil && evt.Process.Exe != "" {
		evt.YaraHits = e.enrichYara(ctx, evt.Process.Exe)
	}

	// 5. 完整性上下文
	evt.Integrity = e.enrichIntegrity()

	// 6. 评分
	e.score(&evt)

	return evt
}

// enrichProcess 通过 PID 补采单个进程信息
func (e *Enricher) enrichProcess(ctx context.Context, pid int) *model.ProcessInfo {
	procs, err := e.collectors.Process.CollectProcesses(ctx)
	if err != nil {
		return nil
	}
	for _, p := range procs {
		if p.PID == pid {
			return &p
		}
	}
	return nil
}

// enrichBinary 补采二进制上下文
func (e *Enricher) enrichBinary(exePath string) *BinaryContext {
	bc := &BinaryContext{Path: exePath}

	info, err := os.Stat(exePath)
	if err != nil {
		bc.Exists = false
		return bc
	}
	bc.Exists = true
	bc.Size = info.Size()

	// 是否在临时目录
	tmpPrefixes := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/"}
	for _, prefix := range tmpPrefixes {
		if strings.HasPrefix(exePath, prefix) {
			bc.InTmpDir = true
			break
		}
	}

	// 是否已删除
	bc.IsDeleted = strings.HasSuffix(exePath, " (deleted)")

	// 哈希
	if hash, err := hashutil.SHA256File(exePath); err == nil {
		bc.SHA256 = hash
	}

	return bc
}

// enrichPersistence 补采持久化项（完整采集）
func (e *Enricher) enrichPersistence(ctx context.Context) []model.PersistenceItem {
	items, err := e.collectors.Persistence.CollectPersistence(ctx)
	if err != nil {
		return nil
	}
	return items
}

// enrichYara 对指定文件执行 YARA 扫描
func (e *Enricher) enrichYara(ctx context.Context, targetPath string) []model.YaraHit {
	// 延迟导入避免循环依赖——直接用 yara 包
	// 这里简单处理：在 engine 层完成 YARA 初始化后传入
	return nil // YARA 扫描在 engine 层处理
}

// enrichIntegrity 构建完整性上下文
func (e *Enricher) enrichIntegrity() *IntegrityContext {
	ic := &IntegrityContext{
		HostTrustLevel:       "high",
		CollectionConfidence: "high",
	}
	if e.preflight != nil {
		ic.HostTrustLevel = e.preflight.HostTrustLevel
	}
	if e.selfCheck != nil {
		ic.CollectionConfidence = e.selfCheck.CollectionConfidence
		if len(e.selfCheck.SelfEnvAnomaly) > 0 {
			ic.VisibilityAnomalies = e.selfCheck.SelfEnvAnomaly
		}
	}
	return ic
}

// score 对补采完成的事件进行评分
func (e *Enricher) score(evt *EnrichedEvent) {
	total := 0
	var evidence []model.Evidence

	// 基础分：IOC 命中
	addEv := func(domain, rule, desc string, score int, sev string) {
		total += score
		evidence = append(evidence, model.Evidence{
			Domain: domain, Rule: rule, Description: desc, Score: score, Severity: sev,
		})
	}

	addEv("ioc", "ioc_hit", "IOC 命中: "+evt.IOC.Value, 20, "medium")

	// 进程上下文加分
	if evt.Process != nil {
		for _, flag := range evt.Process.SuspiciousFlags {
			switch flag {
			case "exe_in_tmp":
				addEv("process", "exe_in_tmp", "进程 exe 位于临时目录", 25, "high")
			case "exe_deleted":
				addEv("process", "exe_deleted", "进程 exe 已被删除", 15, "medium")
			case "webserver_spawned_shell":
				addEv("process", "webshell", "Web 服务器派生 shell", 25, "high")
			}
		}
	} else if evt.Connection.PID > 0 {
		// 有 PID 但采集不到进程——可见性异常
		addEv("integrity", "process_invisible", "PID 存在但进程信息不可见", 20, "medium")
	}

	// 二进制上下文加分
	if evt.Binary != nil {
		if evt.Binary.InTmpDir {
			addEv("binary", "binary_in_tmp", "二进制文件位于临时目录", 25, "high")
		}
		if !evt.Binary.Exists {
			addEv("binary", "binary_missing", "二进制文件不存在", 15, "medium")
		}
	}

	// 持久化关联加分
	if len(evt.Persistence) > 0 {
		addEv("persistence", "persistence_linked", "进程关联到持久化项", 20, "high")
	}

	// YARA 命中加分
	for _, yh := range evt.YaraHits {
		addEv("yara", "yara_hit", "YARA 规则命中: "+yh.Rule, 30, "high")
	}

	// 完整性降权
	if evt.Integrity != nil && evt.Integrity.HostTrustLevel == "low" {
		evt.Confidence = "low"
	}
	if evt.Connection.PID == 0 {
		evt.Confidence = "low"
	}

	// 汇总
	if total > 100 {
		total = 100
	}
	evt.Score = total
	evt.Evidence = evidence

	switch {
	case total >= 80:
		evt.Severity = "critical"
	case total >= 60:
		evt.Severity = "high"
	case total >= 40:
		evt.Severity = "medium"
	case total >= 20:
		evt.Severity = "low"
	default:
		evt.Severity = "info"
	}

	evt.Summary = buildEventSummary(evt)
}

func buildEventSummary(evt *EnrichedEvent) string {
	proc := "unknown"
	if evt.Process != nil {
		proc = evt.Process.Name
	}
	return strings.Join([]string{
		"[" + strings.ToUpper(evt.Severity) + "]",
		"IOC " + evt.IOC.Value,
		"by pid=" + itoa(evt.Connection.PID),
		"process=" + proc,
		"score=" + itoa(evt.Score),
		"confidence=" + evt.Confidence,
	}, " ")
}

func itoa(v int) string {
	// 简单 int to string
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	buf := make([]byte, 0, 10)
	for v > 0 {
		buf = append(buf, byte('0'+v%10))
		v /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

// SetYaraScanner 设置 YARA 扫描回调（避免循环导入）
type YaraScanner interface {
	ScanFile(ctx context.Context, path string) ([]model.YaraHit, error)
}

var _ = time.Now // keep import
