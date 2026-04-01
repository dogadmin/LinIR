package watch

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// ConnKey 生成统一的连接 5 元组键，跨平台所有匹配/去重/pending 必须使用此函数。
func ConnKey(c model.ConnectionInfo) string {
	return fmt.Sprintf("%s:%s:%d:%s:%d", c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort)
}

// IOC 表示一条 IOC 指标
type IOC struct {
	Type  string   `json:"type"`  // "ip" | "domain"
	Value string   `json:"value"` // IP 地址或域名
	Tags  []string `json:"tags,omitempty"`
}

// IOCMatch 表示一次 IOC 与连接的匹配
type IOCMatch struct {
	IOC       IOC    `json:"ioc"`
	MatchType string `json:"match_type"` // "direct_ip" | "direct_domain" | "resolved_ip"
}

// HitEvent 表示一次 IOC 命中事件（未补采）
type HitEvent struct {
	Timestamp  time.Time            `json:"timestamp"`
	IOC        IOC                  `json:"ioc"`
	MatchType  string               `json:"match_type"`
	Connection model.ConnectionInfo `json:"connection"`
	// 事件溯源
	SourceStage string `json:"source_stage,omitempty"` // conntrack_new / nf_conntrack_poll / proc_poll / bpf_syn / macos_conn_poll
}

// WatchMetrics 跨平台观测计数器
type WatchMetrics struct {
	RawEventsTotal           atomic.Int64
	IOCMatchedTotal          atomic.Int64
	PIDResolvedImmediate     atomic.Int64
	PIDResolvedDeferred      atomic.Int64
	PIDUnresolved            atomic.Int64
	OutputEmitted            atomic.Int64
	OutputDeduped            atomic.Int64
	OutputRateLimited        atomic.Int64
	OutputWhitelisted        atomic.Int64
	PendingCurrent           atomic.Int64
	EventChannelOverflow     atomic.Int64
}

// TriggerDecision 表示去重/频控的决策结果
type TriggerDecision struct {
	ShouldEnrich bool   `json:"should_enrich"`
	Deduped      bool   `json:"deduped"`
	RateLimited  bool   `json:"rate_limited"`
	Reason       string `json:"reason,omitempty"`
}

// EnrichedEvent 表示补采完成的完整命中事件
type EnrichedEvent struct {
	Timestamp   time.Time            `json:"timestamp"`
	EventID     string               `json:"event_id"`
	IOC         IOC                  `json:"ioc"`
	MatchType   string               `json:"match_type"`
	Connection  model.ConnectionInfo `json:"connection"`
	Process     *model.ProcessInfo   `json:"process,omitempty"`
	Binary      *BinaryContext       `json:"binary,omitempty"`
	Persistence []model.PersistenceItem `json:"persistence_links,omitempty"`
	YaraHits    []model.YaraHit      `json:"yara_hits,omitempty"`
	Integrity   *IntegrityContext    `json:"integrity,omitempty"`
	Score       int                  `json:"score"`
	Severity    string               `json:"severity"`
	Confidence  string               `json:"confidence"`
	Evidence    []model.Evidence     `json:"evidence"`
	Summary     string               `json:"summary"`
	// 事件溯源
	SourceStage     string `json:"source_stage,omitempty"`      // conntrack_new / bpf_syn / proc_poll / ...
	PIDResolveState string `json:"pid_resolve_state,omitempty"` // immediate / deferred / unresolved
	DedupeKey       string `json:"dedupe_key,omitempty"`
}

// BinaryContext 表示命中进程对应的二进制上下文
type BinaryContext struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size"`
	Exists    bool   `json:"exists"`
	InTmpDir  bool   `json:"in_tmp_dir"`
	IsDeleted bool   `json:"is_deleted"`
}

// IntegrityContext 表示命中时的完整性上下文
type IntegrityContext struct {
	HostTrustLevel      string   `json:"host_trust_level"`
	CollectionConfidence string  `json:"collection_confidence"`
	VisibilityAnomalies []string `json:"visibility_anomalies,omitempty"`
}

// Snapshot 表示一次连接快照
type Snapshot struct {
	CollectedAt time.Time              `json:"collected_at"`
	Connections []model.ConnectionInfo `json:"connections"`
	Platform    string                 `json:"platform"`
}

// WatchConfig 表示 watch 模式的运行配置
type WatchConfig struct {
	IOCFile      string        // IOC 文件路径
	WhitelistFile string       // 白名单文件路径（可选）
	Duration     time.Duration // 监控总时长（0=无限）
	Interval     time.Duration // 轮询间隔
	OutputDir    string        // 输出目录
	JSONOutput   bool          // 是否输出 JSON
	TextOutput   bool          // 是否输出文本
	BundleOutput bool          // 是否输出 bundle
	DedupeWindow time.Duration // 去重时间窗口
	MaxEvents    int           // 每分钟最大事件数（0=不限）
	YaraRules    string        // YARA 规则路径（可选）
	Interface    string        // 网络接口名（可选，空=自动检测）
	Verbose      bool
}
