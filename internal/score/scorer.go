package score

import (
	"fmt"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// Compute 根据采集和分析后的全部数据计算风险评分。
func Compute(result *model.CollectionResult) *model.ScoreResult {
	sr := &model.ScoreResult{
		Confidence: result.SelfCheck.CollectionConfidence,
	}

	// 1. 进程维度评分
	scoreProcesses(sr, result.Processes)

	// 2. 网络维度评分
	scoreNetwork(sr, result.Connections)

	// 3. 持久化维度评分
	scorePersistence(sr, result.Persistence)

	// 4. 完整性维度评分
	scoreIntegrity(sr, result.Integrity, &result.Preflight)

	// 5. YARA 维度评分
	scoreYara(sr, result.YaraHits)

	// 6. 计算总分（上限 100）
	for _, e := range sr.Evidence {
		sr.Total += e.Score
	}
	if sr.Total > 100 {
		sr.Total = 100
	}

	// 7. 确定 severity
	sr.Severity = severityFromScore(sr.Total)

	// 8. 生成摘要
	sr.Summary = buildSummary(sr)

	return sr
}

func scoreProcesses(sr *model.ScoreResult, procs []model.ProcessInfo) {
	for _, p := range procs {
		for _, flag := range p.SuspiciousFlags {
			switch flag {
			case "exe_in_tmp":
				addEvidence(sr, "process", "exe_in_tmp",
					fmt.Sprintf("PID %d (%s) 可执行文件位于临时目录", p.PID, p.Name), 25, "high")
			case "exe_deleted":
				addEvidence(sr, "process", "exe_deleted",
					fmt.Sprintf("PID %d (%s) 可执行文件已被删除", p.PID, p.Name), 20, "medium")
			case "interpreter_established_outbound":
				addEvidence(sr, "process", "interpreter_network",
					fmt.Sprintf("解释器 PID %d (%s) 有活跃外连", p.PID, p.Name), 20, "medium")
			case "persistent_and_networked":
				addEvidence(sr, "process", "persistent_networked",
					fmt.Sprintf("PID %d (%s) 同时具有持久化和网络连接", p.PID, p.Name), 25, "high")
			case "webserver_spawned_shell":
				addEvidence(sr, "process", "webshell_indicator",
					fmt.Sprintf("Web 服务器子进程 PID %d (%s) 为 shell", p.PID, p.Name), 25, "high")
			case "fake_kernel_thread":
				addEvidence(sr, "process", "fake_kthread",
					fmt.Sprintf("PID %d (%s) 伪装内核线程(PPID≠2)", p.PID, p.Name), 20, "medium")
			case "shell_spawned_interpreter_with_network":
				addEvidence(sr, "process", "shell_interp_net",
					fmt.Sprintf("PID %d (%s) 由 shell 启动且有网络连接", p.PID, p.Name), 20, "medium")
			}
		}
	}
}

func scoreNetwork(sr *model.ScoreResult, conns []model.ConnectionInfo) {
	orphanCount := 0
	for _, c := range conns {
		for _, flag := range c.SuspiciousFlags {
			switch {
			case flag == "orphan_active_connection":
				orphanCount++
			case flag == "raw_socket":
				addEvidence(sr, "network", "raw_socket",
					fmt.Sprintf("Raw socket %s:%d", c.LocalAddress, c.LocalPort), 15, "medium")
			case strings.HasPrefix(flag, "suspicious_remote_port:"):
				addEvidence(sr, "network", "suspicious_port",
					fmt.Sprintf("连接到可疑端口 %s:%d (%s)", c.RemoteAddress, c.RemotePort, flag), 20, "high")
			}
		}
	}
	if orphanCount > 0 {
		addEvidence(sr, "network", "orphan_connections",
			fmt.Sprintf("%d 个无归属进程的活跃连接", orphanCount), 20, "medium")
	}
}

func scorePersistence(sr *model.ScoreResult, items []model.PersistenceItem) {
	for _, item := range items {
		for _, flag := range item.RiskFlags {
			switch flag {
			case "target_in_tmp":
				addEvidence(sr, "persistence", "persist_in_tmp",
					fmt.Sprintf("%s (%s) 目标位于临时目录", item.Path, item.Type), 25, "high")
			case "system_wide_preload":
				addEvidence(sr, "persistence", "ld_preload",
					fmt.Sprintf("系统级 ld.so.preload: %s", item.Target), 30, "high")
			case "dev_tcp_reverse_shell":
				addEvidence(sr, "persistence", "reverse_shell",
					fmt.Sprintf("%s 中包含 /dev/tcp 反弹 shell 模式", item.Path), 30, "critical")
			case "pipe_to_shell":
				addEvidence(sr, "persistence", "pipe_shell",
					fmt.Sprintf("%s 中存在管道到 shell 执行", item.Path), 25, "high")
			case "target_running_with_network":
				addEvidence(sr, "persistence", "persist_active_net",
					fmt.Sprintf("%s 目标正在运行且有网络连接", item.Path), 25, "high")
			case "downloads_from_network":
				addEvidence(sr, "persistence", "persist_download",
					fmt.Sprintf("%s 中包含网络下载命令", item.Path), 20, "medium")
			}
		}
	}
}

func scoreIntegrity(sr *model.ScoreResult, ir *model.IntegrityResult, pf *model.PreflightResult) {
	if ir == nil {
		return
	}

	if ir.RootkitSuspected {
		addEvidence(sr, "integrity", "rootkit_suspected",
			"多项可见性异常指向可能存在 rootkit", 30, "critical")
	}
	if len(ir.ModuleViewMismatch) > 0 {
		addEvidence(sr, "integrity", "module_mismatch",
			fmt.Sprintf("内核模块视图不一致: %d 项", len(ir.ModuleViewMismatch)), 25, "high")
	}
	if len(ir.ProcessViewMismatch) > 5 {
		addEvidence(sr, "integrity", "process_visibility",
			fmt.Sprintf("进程视图异常: %d 项不一致", len(ir.ProcessViewMismatch)), 15, "medium")
	}
	if len(ir.NetworkViewMismatch) > 5 {
		addEvidence(sr, "integrity", "network_visibility",
			fmt.Sprintf("网络视图异常: %d 项不一致", len(ir.NetworkViewMismatch)), 15, "medium")
	}

	// 主机信任度
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
			score = 35
		}
		addEvidence(sr, "yara", "yara_hit",
			fmt.Sprintf("YARA 规则 %s 命中: %s", hit.Rule, hit.TargetPath), score, sev)
	}
}

func addEvidence(sr *model.ScoreResult, domain, rule, desc string, score int, severity string) {
	sr.Evidence = append(sr.Evidence, model.Evidence{
		Domain:      domain,
		Rule:        rule,
		Description: desc,
		Score:       score,
		Severity:    severity,
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
