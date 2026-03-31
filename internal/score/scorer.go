package score

import (
	"fmt"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// Compute 根据全部采集和分析数据计算风险评分。
// 设计原则：只为真正的入侵指标评分。干净系统应得 0 分。
func Compute(result *model.CollectionResult) *model.ScoreResult {
	sr := &model.ScoreResult{
		Confidence: result.SelfCheck.CollectionConfidence,
	}

	scoreProcesses(sr, result.Processes)
	scoreNetwork(sr, result.Connections)
	scorePersistence(sr, result.Persistence)
	scoreIntegrity(sr, result.Integrity, &result.Preflight)
	scoreYara(sr, result.YaraHits)

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

func scoreProcesses(sr *model.ScoreResult, procs []model.ProcessInfo) {
	for _, p := range procs {
		if len(p.SuspiciousFlags) == 0 {
			continue
		}
		details := map[string]interface{}{
			"pid":      p.PID,
			"ppid":     p.PPID,
			"name":     p.Name,
			"exe":      p.Exe,
			"username": p.Username,
			"cmdline":  p.Cmdline,
		}
		for _, flag := range p.SuspiciousFlags {
			switch flag {
			case "exe_in_tmp":
				addEvidenceWithDetails(sr, "process", "exe_in_tmp",
					fmt.Sprintf("PID %d (%s) 可执行文件位于临时目录", p.PID, p.Name), 25, "high", details)
			case "exe_deleted":
				addEvidenceWithDetails(sr, "process", "exe_deleted",
					fmt.Sprintf("PID %d (%s) 可执行文件已被删除", p.PID, p.Name), 10, "medium", details)
			case "webserver_spawned_shell":
				addEvidenceWithDetails(sr, "process", "webshell_indicator",
					fmt.Sprintf("Web 服务器子进程 PID %d (%s) 为 shell", p.PID, p.Name), 25, "high", details)
			case "fake_kernel_thread":
				addEvidenceWithDetails(sr, "process", "fake_kthread",
					fmt.Sprintf("PID %d (%s) 伪装内核线程(PPID≠2)", p.PID, p.Name), 20, "high", details)
			case "persistent_and_networked":
				addEvidenceWithDetails(sr, "process", "persistent_networked",
					fmt.Sprintf("PID %d (%s) 同时具有持久化和网络连接", p.PID, p.Name), 15, "medium", details)
			}
		}
	}
}

func scoreNetwork(sr *model.ScoreResult, conns []model.ConnectionInfo) {
	orphanCount := 0
	var orphanSamples []map[string]interface{}
	for _, c := range conns {
		if len(c.SuspiciousFlags) == 0 {
			continue
		}
		connDetails := map[string]interface{}{
			"proto":          c.Proto,
			"local_address":  c.LocalAddress,
			"local_port":     c.LocalPort,
			"remote_address": c.RemoteAddress,
			"remote_port":    c.RemotePort,
			"state":          c.State,
			"pid":            c.PID,
			"process_name":   c.ProcessName,
		}
		for _, flag := range c.SuspiciousFlags {
			switch {
			case flag == "orphan_active_connection":
				orphanCount++
				if len(orphanSamples) < 5 {
					orphanSamples = append(orphanSamples, connDetails)
				}
			case strings.HasPrefix(flag, "suspicious_remote_port:"):
				addEvidenceWithDetails(sr, "network", "suspicious_port",
					fmt.Sprintf("连接到可疑端口 %s:%d (%s)", c.RemoteAddress, c.RemotePort, flag), 20, "high", connDetails)
			}
		}
	}
	if orphanCount > 3 {
		addEvidenceWithDetails(sr, "network", "orphan_connections",
			fmt.Sprintf("%d 个无归属进程的活跃连接", orphanCount), 10, "medium",
			map[string]interface{}{"count": orphanCount, "samples": orphanSamples})
	}
}

func scorePersistence(sr *model.ScoreResult, items []model.PersistenceItem) {
	for _, item := range items {
		if len(item.RiskFlags) == 0 {
			continue
		}
		details := map[string]interface{}{
			"type":       item.Type,
			"path":       item.Path,
			"target":     item.Target,
			"user_scope": item.UserScope,
		}
		for _, flag := range item.RiskFlags {
			switch flag {
			case "target_in_tmp":
				addEvidenceWithDetails(sr, "persistence", "persist_in_tmp",
					fmt.Sprintf("%s (%s) 目标位于临时目录", item.Path, item.Type), 25, "high", details)
			case "system_wide_preload":
				addEvidenceWithDetails(sr, "persistence", "ld_preload",
					fmt.Sprintf("系统级 ld.so.preload: %s", item.Target), 30, "high", details)
			case "dev_tcp_reverse_shell":
				addEvidenceWithDetails(sr, "persistence", "reverse_shell",
					fmt.Sprintf("%s 中包含 /dev/tcp 反弹 shell 模式", item.Path), 30, "critical", details)
			case "pipe_to_shell":
				addEvidenceWithDetails(sr, "persistence", "pipe_shell",
					fmt.Sprintf("%s 中存在 curl/wget 管道到 shell 执行", item.Path), 15, "medium", details)
			case "ld_preload_export":
				addEvidenceWithDetails(sr, "persistence", "ld_preload",
					fmt.Sprintf("shell profile %s 中设置 LD_PRELOAD", item.Path), 30, "high", details)
			case "dyld_inject_export":
				addEvidenceWithDetails(sr, "persistence", "ld_preload",
					fmt.Sprintf("shell profile %s 中设置 DYLD_INSERT_LIBRARIES", item.Path), 30, "high", details)
			case "ld_preload_in_env":
				addEvidenceWithDetails(sr, "persistence", "ld_preload",
					fmt.Sprintf("systemd unit %s Environment 含 LD_PRELOAD", item.Path), 30, "high", details)
			case "target_running_with_network":
				addEvidenceWithDetails(sr, "persistence", "persist_active_net",
					fmt.Sprintf("%s 目标正在运行且有网络连接", item.Path), 15, "medium", details)
			}
		}
	}
}

func scoreIntegrity(sr *model.ScoreResult, ir *model.IntegrityResult, pf *model.PreflightResult) {
	if ir != nil {
		if ir.RootkitSuspected {
			addEvidenceWithDetails(sr, "integrity", "rootkit_suspected",
				"多项可见性异常指向可能存在 rootkit", 30, "critical", map[string]interface{}{
					"process_view_mismatch": ir.ProcessViewMismatch,
					"network_view_mismatch": ir.NetworkViewMismatch,
					"module_view_mismatch":  ir.ModuleViewMismatch,
					"visibility_anomalies":  ir.VisibilityAnomalies,
				})
		}
		if len(ir.ModuleViewMismatch) > 0 {
			addEvidenceWithDetails(sr, "integrity", "module_mismatch",
				fmt.Sprintf("内核模块视图不一致: %d 项", len(ir.ModuleViewMismatch)), 25, "high",
				map[string]interface{}{"modules": ir.ModuleViewMismatch})
		}
	}
	if pf.HostTrustLevel == "low" {
		addEvidence(sr, "integrity", "host_trust_low",
			"主机环境可信度低(loader 劫持/可见性风险)", 20, "medium")
	}
}

func scoreYara(sr *model.ScoreResult, hits []model.YaraHit) {
	for _, hit := range hits {
		sev := "high"
		score := 30
		if hit.SeverityHint == "critical" {
			sev = "critical"
		}
		addEvidenceWithDetails(sr, "yara", "yara_hit",
			fmt.Sprintf("YARA 规则 %s 命中: %s", hit.Rule, hit.TargetPath), score, sev,
			map[string]interface{}{
				"rule":        hit.Rule,
				"target_path": hit.TargetPath,
				"target_type": hit.TargetType,
				"strings":     hit.Strings,
				"meta":        hit.Meta,
				"linked_pid":  hit.LinkedPID,
			})
	}
}

func addEvidence(sr *model.ScoreResult, domain, rule, desc string, score int, severity string) {
	addEvidenceWithDetails(sr, domain, rule, desc, score, severity, nil)
}

func addEvidenceWithDetails(sr *model.ScoreResult, domain, rule, desc string, score int, severity string, details map[string]interface{}) {
	sr.Evidence = append(sr.Evidence, model.Evidence{
		Domain:      domain,
		Rule:        rule,
		Description: desc,
		Score:       score,
		Severity:    severity,
		Details:     details,
	})
}

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
