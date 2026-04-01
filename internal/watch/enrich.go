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

// Enrich 对命中事件进行上下文补采和评分
func (e *Enricher) Enrich(ctx context.Context, hit HitEvent, cache *ScanCache) EnrichedEvent {
	evt := EnrichedEvent{
		Timestamp:  hit.Timestamp,
		EventID:    uuid.NewString()[:8],
		IOC:        hit.IOC,
		MatchType:  hit.MatchType,
		Connection: hit.Connection,
		Confidence: "high",
	}

	// 1. 进程上下文——从缓存 O(1) 查找
	if hit.Connection.PID > 0 && cache != nil {
		evt.Process = cache.FindProcess(hit.Connection.PID)
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

	add := func(domain, rule, desc string, score int, sev string) {
		total += score
		evidence = append(evidence, model.Evidence{
			Domain: domain, Rule: rule, Description: desc, Score: score, Severity: sev,
		})
	}

	add("ioc", "ioc_hit", "IOC 命中: "+evt.IOC.Value, 20, "medium")

	if evt.Process != nil {
		for _, flag := range evt.Process.SuspiciousFlags {
			switch flag {
			case "exe_in_tmp":
				add("process", "exe_in_tmp", "进程 exe 位于临时目录", 25, "high")
			case "exe_deleted":
				add("process", "exe_deleted", "进程 exe 已被删除", 15, "medium")
			case "webserver_spawned_shell":
				add("process", "webshell", "Web 服务器派生 shell", 25, "high")
			}
		}
	} else if evt.Connection.PID > 0 {
		add("integrity", "process_invisible", "PID 存在但进程信息不可见", 20, "medium")
	}

	if evt.Binary != nil {
		if evt.Binary.InTmpDir {
			add("binary", "binary_in_tmp", "二进制位于临时目录", 25, "high")
		}
		if !evt.Binary.Exists {
			add("binary", "binary_missing", "二进制文件不存在", 15, "medium")
		}
	}
	if len(evt.Persistence) > 0 {
		add("persistence", "persistence_linked", "进程关联到持久化项", 20, "high")
	}
	for _, yh := range evt.YaraHits {
		add("yara", "yara_hit", "YARA 规则命中: "+yh.Rule, 30, "high")
	}

	if evt.Integrity != nil && evt.Integrity.HostTrustLevel == "low" {
		evt.Confidence = "low"
	}
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
