package watch

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogadmin/LinIR/internal/collector"
	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/score"
	"github.com/dogadmin/LinIR/pkg/hashutil"
)

// Enricher 负责命中后的上下文补采
type Enricher struct {
	collectors *collector.PlatformCollectors
	preflight  *model.PreflightResult
	selfCheck  *model.SelfCheckResult
	// TTL 缓存：避免 conntrack/BPF 事件驱动模式下每个 hit 都全量采集
	cachedScan *ScanCache
	cacheTime  time.Time
}

const cacheTTL = 3 * time.Second

// NewEnricher 创建补采器
func NewEnricher(collectors *collector.PlatformCollectors, yaraRules string,
	pf *model.PreflightResult, sc *model.SelfCheckResult) *Enricher {
	return &Enricher{
		collectors: collectors,
		preflight:  pf,
		selfCheck:  sc,
	}
}

// ScanCache 保存单次扫描周期内的预采集数据，避免每次命中都全量采集
type ScanCache struct {
	Processes   []model.ProcessInfo
	Persistence []model.PersistenceItem
	procMap     map[int]*model.ProcessInfo
}

// CollectCache 返回预采集缓存。3 秒内重复调用返回同一份缓存，避免事件驱动模式下重复采集。
func (e *Enricher) CollectCache(ctx context.Context) *ScanCache {
	if e.cachedScan != nil && time.Since(e.cacheTime) < cacheTTL {
		return e.cachedScan
	}
	cache := &ScanCache{}
	procs, err := e.collectors.Process.CollectProcesses(ctx)
	if err == nil {
		cache.Processes = procs
	}
	items, err := e.collectors.Persistence.CollectPersistence(ctx)
	if err == nil {
		cache.Persistence = items
	}
	e.cachedScan = cache
	e.cacheTime = time.Now()
	return cache
}

// FindProcess 从缓存中查找进程（延迟构建索引，O(1) 查找）
func (c *ScanCache) FindProcess(pid int) *model.ProcessInfo {
	if c.procMap == nil {
		c.procMap = make(map[int]*model.ProcessInfo, len(c.Processes))
		for i := range c.Processes {
			c.procMap[c.Processes[i].PID] = &c.Processes[i]
		}
	}
	return c.procMap[pid]
}

// ResolveHitPID 为事件驱动命中（conntrack/BPF，PID=0）快速定向解析进程信息。
// 仅使用 ResolveConnectionPID（Linux: /proc/net/tcp 找 inode → 定向搜索 PID，~10-50ms）。
// 不做全量 CollectConnections（~200-500ms），因为调用方会重试多次，慢速回退会把重试窗口浪费掉。
func ResolveHitPID(ctx context.Context, hit *HitEvent, collectors *collector.PlatformCollectors) {
	if hit.Connection.PID > 0 {
		return
	}
	if pid, name := collectors.Network.ResolveConnectionPID(hit.Connection); pid > 0 {
		hit.Connection.PID = pid
		hit.Connection.ProcessName = name
	}
}

// Enrich 对命中事件进行上下文补采和评分
func (e *Enricher) Enrich(ctx context.Context, hit HitEvent, cache *ScanCache) EnrichedEvent {
	resolveState := "unresolved"
	if hit.Connection.PID > 0 {
		resolveState = "immediate"
		// 事件驱动来源（conntrack/BPF）的 PID 都是事后解析的
		if hit.SourceStage == "conntrack_new" || hit.SourceStage == "bpf_syn" || hit.SourceStage == "bpf_udp" {
			resolveState = "deferred"
		}
	}

	evt := EnrichedEvent{
		Timestamp:       hit.Timestamp,
		EventID:         uuid.NewString()[:8],
		IOC:             hit.IOC,
		MatchType:       hit.MatchType,
		Connection:      hit.Connection,
		Confidence:      "high",
		SourceStage:     hit.SourceStage,
		PIDResolveState: resolveState,
		DedupeKey:       dedupeKey(hit),
	}

	// 1. 进程上下文——从缓存 O(1) 查找
	// PID 应在调用 Enrich 前已由 ResolveHitPID 解析（事件驱动模式）
	// 或在 CollectConnections 中已设置（轮询模式）
	if hit.Connection.PID > 0 && cache != nil {
		evt.Process = cache.FindProcess(hit.Connection.PID)
	}
	// 回退：进程已退出但连接上记录了进程名（来自 /proc/<pid>/comm 或 proc_pidfdinfo）
	if evt.Process == nil && hit.Connection.PID > 0 && hit.Connection.ProcessName != "" {
		evt.Process = &model.ProcessInfo{
			PID:  hit.Connection.PID,
			Name: hit.Connection.ProcessName,
		}
	}
	if evt.Process == nil && hit.Connection.PID > 0 {
		evt.Confidence = "medium"
	}
	if hit.Connection.PID == 0 {
		evt.Confidence = "medium"
	}

	// 2. 二进制上下文
	if evt.Process != nil && evt.Process.Exe != "" {
		evt.Binary = enrichBinary(evt.Process.Exe)
	}

	// 3. 持久化关联——从缓存过滤
	if evt.Process != nil && cache != nil {
		for _, item := range cache.Persistence {
			if item.Target == evt.Process.Exe || strings.Contains(item.Target, evt.Process.Name) {
				evt.Persistence = append(evt.Persistence, item)
			}
		}
	}

	// 4. 完整性上下文
	evt.Integrity = e.enrichIntegrity()

	// 5. 评分
	scoreEvent(&evt)

	return evt
}

func enrichBinary(exePath string) *BinaryContext {
	bc := &BinaryContext{Path: exePath}
	info, err := os.Stat(exePath)
	if err != nil {
		bc.Exists = false
		return bc
	}
	bc.Exists = true
	bc.Size = info.Size()
	bc.IsDeleted = strings.HasSuffix(exePath, " (deleted)")

	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/"} {
		if strings.HasPrefix(exePath, prefix) {
			bc.InTmpDir = true
			break
		}
	}
	if hash, err := hashutil.SHA256File(exePath); err == nil {
		bc.SHA256 = hash
	}
	return bc
}

func (e *Enricher) enrichIntegrity() *IntegrityContext {
	ic := &IntegrityContext{HostTrustLevel: "high", CollectionConfidence: "high"}
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

func scoreEvent(evt *EnrichedEvent) {
	total := 0
	var evidence []model.Evidence
	ruleSet := make(map[string]bool) // 用于组合项检查

	add := func(domain, rule, desc string, score int, sev string) {
		total += score
		evidence = append(evidence, model.Evidence{
			Domain: domain, Rule: rule, Description: desc, Score: score, Severity: sev,
		})
		ruleSet[rule] = true
	}

	// ===== 基础分 =====
	add("ioc", score.RuleIOCHit, "IOC 命中: "+evt.IOC.Value, 20, "medium")

	// ===== 进程/二进制域 =====
	if evt.Process != nil {
		for _, flag := range evt.Process.SuspiciousFlags {
			switch flag {
			case "exe_in_tmp":
				add("process", score.RuleExeInTmp, "进程 exe 位于临时目录", 10, "low")
				if score.IsInterpreterProcess(evt.Process.Name) {
					add("process", score.RuleExeInTmpInterpreter, "临时目录 shell/interpreter", 10, "medium")
				}
			case "exe_deleted":
				add("process", score.RuleExeDeleted, "进程 exe 已删除", 5, "low")
			case "webserver_spawned_shell":
				add("process", score.RuleWebshellStrong, "Web 服务器派生 shell", 25, "high")
			}
		}
	} else if evt.Connection.PID > 0 {
		add("integrity", score.RuleProcessInvisible, "PID 存在但进程信息不可见", 5, "low")
	}

	if evt.Binary != nil {
		if evt.Binary.InTmpDir {
			add("binary", score.RuleBinaryInTmp, "二进制位于临时目录", 10, "low")
		}
		if !evt.Binary.Exists {
			add("binary", score.RuleBinaryMissing, "二进制文件不存在", 5, "low")
		}
	}

	// ===== 持久化域 =====
	if len(evt.Persistence) > 0 {
		add("persistence", score.RulePersistenceLinked, "进程关联到持久化项", 10, "medium")
		for _, p := range evt.Persistence {
			if score.IsInTmpDir(p.Target) {
				add("persistence", score.RulePersistLinkedAbnorm, "持久化目标路径异常", 5, "high")
				break
			}
		}
	}

	// ===== YARA 域（共享 4 级分层）=====
	for _, yh := range evt.YaraHits {
		s, sev := score.YaraScoreByHint(yh.SeverityHint)
		add("yara", "yara_hit_"+sev, "YARA 规则命中: "+yh.Rule, s, sev)
		if score.IsInTmpDir(yh.TargetPath) {
			add("yara", score.RuleYaraOnTmpBinary, "YARA 命中临时目录目标", 5, "high")
		}
	}

	// ===== 组合增强项 =====
	has := func(rule string) bool { return ruleSet[rule] }

	if has("ioc_hit") && has("exe_in_tmp") {
		add("combo", "combo_ioc_tmp_exec", "IOC 命中 + 临时目录执行", 10, "high")
	}
	if has("ioc_hit") && has("exe_deleted") {
		add("combo", "combo_ioc_deleted_exec", "IOC 命中 + 已删除 exe", 5, "medium")
	}
	if has("ioc_hit") && has("persistence_linked") {
		add("combo", "combo_ioc_persistence", "IOC 命中 + 持久化关联", 10, "high")
	}
	if has("ioc_hit") && (has("yara_hit_high") || has("yara_hit_critical")) {
		add("combo", "combo_ioc_yara", "IOC 命中 + YARA 高危", 10, "high")
	}
	if has("webshell_strong") {
		add("combo", "combo_ioc_webshell", "IOC 命中 + Webshell", 15, "critical")
	}
	if has("persistence_linked") && (has("yara_hit_high") || has("yara_hit_critical")) {
		add("combo", "combo_ioc_persist_yara", "IOC + 持久化 + YARA", 15, "critical")
	}

	// ===== confidence 规则 =====
	if evt.Integrity != nil && evt.Integrity.HostTrustLevel == "low" {
		evt.Confidence = "low"
	}
	if evt.Process == nil && evt.Connection.PID > 0 {
		if evt.Confidence == "high" {
			evt.Confidence = "medium"
		}
	}
	if evt.Connection.PID == 0 {
		if evt.Confidence == "high" {
			evt.Confidence = "medium"
		}
	}

	// ===== 汇总 =====
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

	proc := "unknown"
	if evt.Process != nil {
		proc = evt.Process.Name
	}
	evt.Summary = "[" + strings.ToUpper(evt.Severity) + "] IOC " + evt.IOC.Value +
		" pid=" + strconv.Itoa(evt.Connection.PID) +
		" process=" + proc +
		" score=" + strconv.Itoa(evt.Score) +
		" confidence=" + evt.Confidence
}

// isInterpreterNameWatch and isInTmpWatch moved to score.IsInterpreterProcess / score.IsInTmpDir
