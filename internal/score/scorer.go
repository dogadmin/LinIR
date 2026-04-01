package score

import (
	"fmt"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// Compute 根据全部采集和分析数据计算风险评分。
//
// 设计原则：
//   - 干净系统应得 0 分
//   - 单点线索低分化（exe_in_tmp +10, exe_deleted +5）
//   - 组合证据高分化（tmp + network + persist = 高危链路）
//   - 完整性异常主要影响 confidence，不直接堆高恶意分
//   - YARA 按 severity_hint 分 4 级
//   - 总分 0-100，上限 100
func Compute(result *model.CollectionResult) *model.ScoreResult {
	sr := &model.ScoreResult{
		Confidence: result.SelfCheck.CollectionConfidence,
	}

	// 构建辅助索引
	ctx := buildScoringContext(result)

	scoreProcesses(sr, result.Processes, ctx)
	scoreNetwork(sr, result.Connections)
	scorePersistence(sr, result.Persistence, ctx)
	scoreIntegrity(sr, result.Integrity, &result.Preflight)
	scoreYara(sr, result.YaraHits, ctx)
	scoreCombos(sr, result, ctx)

	for _, e := range sr.Evidence {
		sr.Total += e.Score
	}
	if sr.Total > 100 {
		sr.Total = 100
	}

	sr.Severity = severityFromScore(sr.Total)
	sr.Summary = buildSummary(sr)

	return sr
}

// ========== 评分上下文 ==========

// scoringContext 预构建的交叉索引，供组合规则查询
type scoringContext struct {
	// PID → 是否有活跃网络连接
	pidNetworked map[int]bool
	// PID → ProcessInfo 快速查找
	pidProc map[int]*model.ProcessInfo
	// exe 路径 → PID 列表
	exePIDs map[string][]int
	// 持久化目标 → 是否正在运行
	persistTargetRunning map[string]bool
	// 持久化目标 → 是否有网络连接
	persistTargetNetworked map[string]bool
	// 有 YARA 命中的路径集合
	yaraHitPaths map[string]bool
}

func buildScoringContext(result *model.CollectionResult) *scoringContext {
	ctx := &scoringContext{
		pidNetworked:           make(map[int]bool),
		pidProc:                make(map[int]*model.ProcessInfo),
		exePIDs:                make(map[string][]int),
		persistTargetRunning:   make(map[string]bool),
		persistTargetNetworked: make(map[string]bool),
		yaraHitPaths:           make(map[string]bool),
	}

	for i := range result.Processes {
		p := &result.Processes[i]
		ctx.pidProc[p.PID] = p
		if p.Exe != "" {
			ctx.exePIDs[p.Exe] = append(ctx.exePIDs[p.Exe], p.PID)
		}
	}

	for _, c := range result.Connections {
		if c.PID > 0 && (c.State == "ESTABLISHED" || c.State == "SYN_SENT") {
			ctx.pidNetworked[c.PID] = true
		}
	}

	for _, item := range result.Persistence {
		for _, flag := range item.RiskFlags {
			if flag == "target_currently_running" {
				ctx.persistTargetRunning[item.Target] = true
			}
			if flag == "target_running_with_network" {
				ctx.persistTargetNetworked[item.Target] = true
			}
		}
	}

	for _, yh := range result.YaraHits {
		ctx.yaraHitPaths[yh.TargetPath] = true
	}

	return ctx
}

// ========== 辅助函数 ==========

func add(sr *model.ScoreResult, domain, rule, desc string, score int, severity string, details map[string]interface{}) {
	sr.Evidence = append(sr.Evidence, model.Evidence{
		Domain: domain, Rule: rule, Description: desc,
		Score: score, Severity: severity, Details: details,
	})
}

func hasFlag(flags []string, target string) bool {
	for _, f := range flags {
		if f == target {
			return true
		}
	}
	return false
}

func isInTmp(path string) bool {
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func isInterpreterName(name string) bool {
	for _, n := range []string{"bash", "sh", "zsh", "python", "python3", "perl", "ruby", "php", "node"} {
		if name == n {
			return true
		}
	}
	return false
}

func procDetails(p *model.ProcessInfo) map[string]interface{} {
	return map[string]interface{}{
		"pid": p.PID, "ppid": p.PPID, "name": p.Name,
		"exe": p.Exe, "username": p.Username, "cmdline": p.Cmdline,
	}
}

func addIntegrityFlag(sr *model.ScoreResult, flag string) {
	for _, f := range sr.IntegrityFlags {
		if f == flag {
			return
		}
	}
	sr.IntegrityFlags = append(sr.IntegrityFlags, flag)
}

func downgradeConfidence(sr *model.ScoreResult, level, reason string) {
	ranks := map[string]int{"high": 3, "medium": 2, "low": 1}
	if ranks[level] < ranks[sr.Confidence] {
		sr.Confidence = level
	}
	sr.ConfidenceFactors = append(sr.ConfidenceFactors, reason)
}

// ========== 进程域 ==========

func scoreProcesses(sr *model.ScoreResult, procs []model.ProcessInfo, ctx *scoringContext) {
	for _, p := range procs {
		if len(p.SuspiciousFlags) == 0 {
			continue
		}
		d := procDetails(&p)
		networked := ctx.pidNetworked[p.PID]

		for _, flag := range p.SuspiciousFlags {
			switch flag {
			case "exe_in_tmp":
				add(sr, "process", "exe_in_tmp", fmt.Sprintf("PID %d (%s) 可执行文件位于临时目录", p.PID, p.Name), 10, "low", d)
				if networked {
					add(sr, "process", "exe_in_tmp_networked", fmt.Sprintf("PID %d (%s) 临时目录执行且联网", p.PID, p.Name), 10, "medium", d)
				}
				if isInterpreterName(p.Name) {
					add(sr, "process", "exe_in_tmp_interpreter", fmt.Sprintf("PID %d (%s) 临时目录 shell/interpreter", p.PID, p.Name), 5, "medium", d)
				}

			case "exe_deleted":
				add(sr, "process", "exe_deleted", fmt.Sprintf("PID %d (%s) 可执行文件已删除", p.PID, p.Name), 5, "low", d)
				if networked {
					add(sr, "process", "exe_deleted_networked", fmt.Sprintf("PID %d (%s) 已删除且联网", p.PID, p.Name), 5, "medium", d)
				}

			case "webserver_spawned_shell":
				if networked {
					add(sr, "process", "webshell_indicator_strong", fmt.Sprintf("PID %d (%s) Web 服务派生 shell 且有连接", p.PID, p.Name), 25, "high", d)
				} else {
					add(sr, "process", "webshell_indicator_weak", fmt.Sprintf("PID %d (%s) Web 服务派生 shell", p.PID, p.Name), 10, "medium", d)
				}

			case "fake_kernel_thread":
				add(sr, "process", "fake_kthread", fmt.Sprintf("PID %d (%s) 伪装内核线程", p.PID, p.Name), 10, "medium", d)
				if networked {
					add(sr, "process", "fake_kthread_networked", fmt.Sprintf("PID %d (%s) 伪内核线程且联网", p.PID, p.Name), 10, "high", d)
				}

			case "persistent_and_networked":
				add(sr, "process", "persistent_networked", fmt.Sprintf("PID %d (%s) 持久化且联网", p.PID, p.Name), 10, "medium", d)
				if isInTmp(p.Exe) {
					add(sr, "process", "persistent_networked_abnormal_path", fmt.Sprintf("PID %d (%s) 持久化联网且路径异常", p.PID, p.Name), 5, "high", d)
				}
			}
		}
	}
}

// ========== 网络域 ==========

func scoreNetwork(sr *model.ScoreResult, conns []model.ConnectionInfo) {
	orphanCount := 0
	for _, c := range conns {
		if len(c.SuspiciousFlags) == 0 {
			continue
		}
		d := map[string]interface{}{
			"proto": c.Proto, "remote_address": c.RemoteAddress, "remote_port": c.RemotePort,
			"pid": c.PID, "process_name": c.ProcessName,
		}
		for _, flag := range c.SuspiciousFlags {
			switch {
			case flag == "orphan_active_connection":
				orphanCount++
			case strings.HasPrefix(flag, "suspicious_remote_port:"):
				// 单看端口仅作线索
				add(sr, "network", "suspicious_port", fmt.Sprintf("连接到可疑端口 %s:%d", c.RemoteAddress, c.RemotePort), 5, "low", d)
			}
		}
	}
	// orphan 不直接加恶意分，进入 integrity_flags
	if orphanCount > 3 {
		addIntegrityFlag(sr, fmt.Sprintf("orphan_active_connections:%d", orphanCount))
		downgradeConfidence(sr, "medium", fmt.Sprintf("%d 个无归属活跃连接", orphanCount))
	}
}

// ========== 持久化域 ==========

func scorePersistence(sr *model.ScoreResult, items []model.PersistenceItem, ctx *scoringContext) {
	for _, item := range items {
		if len(item.RiskFlags) == 0 {
			continue
		}
		d := map[string]interface{}{
			"type": item.Type, "path": item.Path, "target": item.Target, "user_scope": item.UserScope,
		}
		active := ctx.persistTargetRunning[item.Target]
		activeNet := ctx.persistTargetNetworked[item.Target]

		for _, flag := range item.RiskFlags {
			switch flag {
			case "target_in_tmp":
				add(sr, "persistence", "persist_in_tmp", fmt.Sprintf("%s 目标位于临时目录", item.Path), 15, "medium", d)
				if active {
					add(sr, "persistence", "persist_in_tmp_active", fmt.Sprintf("%s 临时目录持久化已激活", item.Path), 10, "high", d)
				}
				if activeNet {
					add(sr, "persistence", "persist_in_tmp_active_net", fmt.Sprintf("%s 临时目录持久化激活且联网", item.Path), 10, "high", d)
				}

			case "system_wide_preload":
				add(sr, "persistence", "global_ld_preload_present", fmt.Sprintf("系统级 ld.so.preload: %s", item.Target), 15, "medium", d)
				if isInTmp(item.Target) || !item.Exists {
					add(sr, "persistence", "preload_path_abnormal", fmt.Sprintf("preload 路径异常: %s", item.Target), 10, "high", d)
				}

			case "dev_tcp_reverse_shell":
				// 区分强弱：看是否有明确的 shell + /dev/tcp 组合
				add(sr, "persistence", "reverse_shell_strong", fmt.Sprintf("%s 反弹 shell 模式", item.Path), 25, "critical", d)
				addIntegrityFlag(sr, "reverse_shell_pattern")
				if active {
					add(sr, "persistence", "reverse_shell_active", fmt.Sprintf("%s 反弹 shell 已激活", item.Path), 10, "critical", d)
				}

			case "pipe_to_shell":
				add(sr, "persistence", "pipe_shell", fmt.Sprintf("%s curl/wget 管道执行", item.Path), 8, "low", d)
				if active {
					add(sr, "persistence", "pipe_shell_active", fmt.Sprintf("%s 管道执行已激活", item.Path), 8, "medium", d)
				}

			case "ld_preload_export":
				add(sr, "persistence", "profile_ld_preload", fmt.Sprintf("shell profile %s 设置 LD_PRELOAD", item.Path), 15, "medium", d)

			case "dyld_inject_export":
				add(sr, "persistence", "profile_dyld_insert", fmt.Sprintf("shell profile %s 设置 DYLD_INSERT_LIBRARIES", item.Path), 15, "medium", d)

			case "ld_preload_in_env":
				add(sr, "persistence", "systemd_env_ld_preload", fmt.Sprintf("systemd unit %s Environment 含 LD_PRELOAD", item.Path), 15, "medium", d)

			case "target_running_with_network":
				add(sr, "persistence", "persist_active_net", fmt.Sprintf("%s 持久化目标运行且联网", item.Path), 10, "medium", d)
				if isInTmp(item.Target) || ctx.yaraHitPaths[item.Target] {
					add(sr, "persistence", "persist_active_net_abnormal", fmt.Sprintf("%s 活跃持久化路径异常或命中YARA", item.Path), 10, "high", d)
				}
			}
		}
	}
}

// ========== 完整性域 ==========

func scoreIntegrity(sr *model.ScoreResult, ir *model.IntegrityResult, pf *model.PreflightResult) {
	if ir != nil {
		if ir.RootkitSuspected {
			add(sr, "integrity", "rootkit_suspected",
				"多项可见性异常指向可能存在 rootkit", 15, "high", map[string]interface{}{
					"process_view_mismatch": ir.ProcessViewMismatch,
					"network_view_mismatch": ir.NetworkViewMismatch,
					"module_view_mismatch":  ir.ModuleViewMismatch,
					"visibility_anomalies":  ir.VisibilityAnomalies,
				})
			addIntegrityFlag(sr, "rootkit_suspected")
			downgradeConfidence(sr, "low", "rootkit_suspected")
		}
		if len(ir.ModuleViewMismatch) > 0 {
			add(sr, "integrity", "module_mismatch",
				fmt.Sprintf("内核模块视图不一致: %d 项", len(ir.ModuleViewMismatch)), 15, "high",
				map[string]interface{}{"modules": ir.ModuleViewMismatch})
			addIntegrityFlag(sr, "module_view_mismatch")
		}
	}

	// host_trust_low 不直接加恶意分，只降 confidence
	if pf != nil && pf.HostTrustLevel == "low" {
		downgradeConfidence(sr, "low", "host_trust_low")
		addIntegrityFlag(sr, "host_trust_low")
		// 仅在有明确 loader 劫持时少量加分
		if len(pf.LoaderAnomaly) > 0 {
			add(sr, "integrity", "host_trust_low_loader",
				"主机环境可信度低且存在 loader 劫持", 10, "medium", nil)
		}
	}
}

// ========== YARA 域 ==========

func scoreYara(sr *model.ScoreResult, hits []model.YaraHit, ctx *scoringContext) {
	for _, hit := range hits {
		d := map[string]interface{}{
			"rule": hit.Rule, "target_path": hit.TargetPath,
			"target_type": hit.TargetType, "strings": hit.Strings,
			"meta": hit.Meta, "linked_pid": hit.LinkedPID,
		}

		// 按 severity_hint 分 4 级
		var score int
		var sev string
		switch hit.SeverityHint {
		case "critical":
			score, sev = 25, "critical"
		case "high":
			score, sev = 20, "high"
		case "medium":
			score, sev = 15, "medium"
		default:
			score, sev = 10, "low"
		}
		add(sr, "yara", "yara_hit_"+sev, fmt.Sprintf("YARA 规则 %s 命中: %s", hit.Rule, hit.TargetPath), score, sev, d)

		// 上下文增强
		if hit.LinkedPID > 0 && ctx.pidNetworked[hit.LinkedPID] {
			add(sr, "yara", "yara_on_active_process", fmt.Sprintf("YARA 命中活跃进程: %s", hit.Rule), 5, "high", d)
		}
		if isInTmp(hit.TargetPath) {
			add(sr, "yara", "yara_abnormal_path_bonus", fmt.Sprintf("YARA 命中临时目录: %s", hit.TargetPath), 5, "high", d)
		}
		if hit.TargetType == "persistence-target" {
			add(sr, "yara", "yara_on_persistence_target", fmt.Sprintf("YARA 命中持久化目标: %s", hit.TargetPath), 5, "high", d)
		}
	}
}

// ========== 组合增强项 ==========

func scoreCombos(sr *model.ScoreResult, result *model.CollectionResult, ctx *scoringContext) {
	// 构建已触发规则集合
	ruleSet := make(map[string]bool)
	for _, e := range sr.Evidence {
		ruleSet[e.Rule] = true
	}

	has := func(rule string) bool { return ruleSet[rule] }

	if has("exe_in_tmp") && (has("yara_hit_low") || has("yara_hit_medium") || has("yara_hit_high") || has("yara_hit_critical")) {
		add(sr, "combo", "combo_tmp_exec_and_yara", "临时目录执行 + YARA 命中", 10, "high", nil)
	}
	if has("exe_in_tmp") && has("persistent_networked") {
		add(sr, "combo", "combo_tmp_exec_and_persist", "临时目录执行 + 持久化联网", 10, "high", nil)
	}
	if has("exe_deleted") && (has("persist_active_net") || has("persistent_networked")) {
		add(sr, "combo", "combo_deleted_and_persist", "已删除进程 + 持久化", 10, "high", nil)
	}
	if has("webshell_indicator_strong") && (has("exe_in_tmp_networked") || has("suspicious_port")) {
		add(sr, "combo", "combo_webshell_and_network", "Webshell 强指标 + 活跃连接", 10, "critical", nil)
		addIntegrityFlag(sr, "webshell_indicator_strong")
	}
	if has("global_ld_preload_present") && has("preload_path_abnormal") {
		add(sr, "combo", "combo_preload_and_active_process", "preload 风险 + 路径异常", 10, "critical", nil)
		addIntegrityFlag(sr, "preload_active_impact")
	}
	if has("persist_active_net") && (has("yara_hit_high") || has("yara_hit_critical")) {
		add(sr, "combo", "combo_persistence_yara_network", "持久化 + YARA + 网络", 15, "critical", nil)
		addIntegrityFlag(sr, "ioc_persist_yara_combo")
	}
	if has("rootkit_suspected") && (has("exe_in_tmp") || has("webshell_indicator_strong") || has("fake_kthread")) {
		add(sr, "combo", "combo_rootkit_plus_active_suspicious", "rootkit 嫌疑 + 活跃可疑进程", 10, "critical", nil)
	}
}

// ========== 通用 ==========

func severityFromScore(total int) string {
	switch {
	case total >= 80:
		return "critical"
	case total >= 60:
		return "high"
	case total >= 40:
		return "medium"
	case total >= 20:
		return "low"
	default:
		return "info"
	}
}

func buildSummary(sr *model.ScoreResult) string {
	if len(sr.Evidence) == 0 {
		return "未发现显著风险指标。"
	}
	domains := map[string]int{}
	for _, e := range sr.Evidence {
		domains[e.Domain] += e.Score
	}
	parts := make([]string, 0, len(domains))
	for d, s := range domains {
		parts = append(parts, fmt.Sprintf("%s(%d)", d, s))
	}
	return fmt.Sprintf("风险评分 %d/100 (%s)。发现 %d 项证据，涉及: %s",
		sr.Total, strings.ToUpper(sr.Severity), len(sr.Evidence), strings.Join(parts, ", "))
}
