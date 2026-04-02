package score

import (
	"fmt"

	"github.com/dogadmin/LinIR/internal/model"
)

// ComputeAnalysis extends the standard scoring with retained and triggerable evidence.
// It modifies the existing ScoreResult in the runtime CollectionResult.
func ComputeAnalysis(result *model.AnalysisResult) {
	if result.Runtime == nil || result.Runtime.Score == nil {
		return
	}
	sr := result.Runtime.Score

	if result.Retained != nil {
		scoreRetained(sr, result.Retained)
	}
	if result.Triggerable != nil {
		scoreTriggerable(sr, result.Triggerable)
	}
	if result.Retained != nil && result.Triggerable != nil {
		scoreCrossState(sr, result)
	}

	// Recompute total
	sr.Total = 0
	for _, e := range sr.Evidence {
		sr.Total += e.Score
	}
	if sr.Total > 100 {
		sr.Total = 100
	}
	sr.Severity = severityFromScore(sr.Total)
	sr.Summary = buildSummary(sr)
}

// ========== Retained 域评分 ==========

func scoreRetained(sr *model.ScoreResult, r *model.RetainedState) {
	// 1. Recently modified persistence — only score if target is suspicious
	for _, c := range r.PersistChanges {
		hasSuspiciousTarget := false
		for _, flag := range c.RiskFlags {
			if flag == "target_in_tmp" || flag == "target_missing" {
				hasSuspiciousTarget = true
				break
			}
		}
		if !hasSuspiciousTarget {
			continue
		}
		d := map[string]interface{}{
			"type": c.Type, "path": c.Path, "target": c.Target,
			"change_type": c.ChangeType, "mod_time": c.ModTime.String(),
		}
		addEvidence(sr, "retained", RuleRetainedPersistChanged,
			fmt.Sprintf("持久化配置近期变更且目标异常: %s (%s)", c.Path, c.ChangeType),
			5, "low", d)

		for _, flag := range c.RiskFlags {
			if flag == "target_in_tmp" {
				addEvidence(sr, "retained", RuleRetainedPersistTmpTarget,
					fmt.Sprintf("近期变更的持久化目标在临时目录: %s", c.Target),
					10, "high", d)
			}
		}
	}

	// 2. Deleted exe artifacts
	for _, a := range r.Artifacts {
		d := map[string]interface{}{
			"type": a.Type, "path": a.Path, "reason": a.Reason,
		}
		switch a.Type {
		case "deleted_exe":
			addEvidence(sr, "retained", RuleRetainedDeletedExe,
				fmt.Sprintf("已删除可执行文件残留: %s (PID %d)", a.Path, a.LinkedPID),
				5, "medium", d)
		case "tmp_executable":
			addEvidence(sr, "retained", RuleRetainedTmpExecutable,
				fmt.Sprintf("临时目录孤立可执行文件: %s", a.Path),
				5, "low", d)
		}
	}

	// 3. Failed login clusters — higher thresholds to reduce noise
	failedLogins := 0
	for _, e := range r.AuthHistory {
		if !e.Success && (e.Type == "failed_login" || e.Type == "ssh_reject") {
			failedLogins++
		}
	}
	if failedLogins >= 100 {
		addEvidence(sr, "retained", RuleRetainedFailedLogins,
			fmt.Sprintf("窗口期内 %d 次登录失败", failedLogins),
			3, "low", map[string]interface{}{"count": failedLogins})
	}
	if failedLogins >= 500 {
		addEvidence(sr, "retained", RuleRetainedFailedLogins+"_brute",
			fmt.Sprintf("窗口期内 %d 次登录失败（疑似暴力破解）", failedLogins),
			8, "medium", map[string]interface{}{"count": failedLogins})
	}
}

// ========== Triggerable 域评分 ==========

func scoreTriggerable(sr *model.ScoreResult, t *model.TriggerableState) {
	allEntries := make([]model.TriggerableEntry, 0, len(t.Autostarts)+len(t.Scheduled)+len(t.Keepalive))
	allEntries = append(allEntries, t.Autostarts...)
	allEntries = append(allEntries, t.Scheduled...)
	allEntries = append(allEntries, t.Keepalive...)

	for _, e := range allEntries {
		if len(e.RiskFlags) == 0 {
			continue
		}
		d := map[string]interface{}{
			"type": e.Type, "category": e.Category, "path": e.Path,
			"target": e.Target, "trigger": e.TriggerCondition,
		}

		for _, flag := range e.RiskFlags {
			switch flag {
			// restart_always: 不单独计分，仅作为数据展示和跨状态组合的输入
			case "target_in_tmp":
				addEvidence(sr, "triggerable", RuleTriggerableTmpAutostart,
					fmt.Sprintf("触发态目标在临时目录: %s → %s", e.Path, e.Target),
					10, "high", d)
			case "dev_tcp_reverse_shell":
				addEvidence(sr, "triggerable", RuleTriggerableReverseShellCron,
					fmt.Sprintf("定时任务包含反弹 shell: %s", e.Path),
					20, "critical", d)
				addIntegrityFlag(sr, "triggerable_reverse_shell")
			case "pipe_to_shell":
				addEvidence(sr, "triggerable", RuleTriggerablePipeShellCron,
					fmt.Sprintf("定时任务包含 curl/wget 管道执行: %s", e.Path),
					5, "low", d)
			}
		}
	}
}

// ========== 跨状态组合评分 ==========

func scoreCrossState(sr *model.ScoreResult, result *model.AnalysisResult) {
	if result.Retained == nil || result.Triggerable == nil {
		return
	}

	// Build set of recently changed persistence paths that have suspicious flags
	type changedInfo struct {
		path  string
		risky bool // has target_in_tmp, target_missing, or other suspicious flags
	}
	changedPaths := make(map[string]changedInfo)
	for _, c := range result.Retained.PersistChanges {
		risky := false
		for _, f := range c.RiskFlags {
			if f == "target_in_tmp" || f == "target_missing" || f == "persistence_file_disappeared" {
				risky = true
				break
			}
		}
		changedPaths[c.Path] = changedInfo{path: c.Path, risky: risky}
	}

	// Build set of triggerable targets with risk info
	type trigInfo struct {
		hasRiskFlags bool
	}
	triggerablePaths := make(map[string]trigInfo)
	allTrig := make([]model.TriggerableEntry, 0, len(result.Triggerable.Autostarts)+len(result.Triggerable.Scheduled)+len(result.Triggerable.Keepalive))
	allTrig = append(allTrig, result.Triggerable.Autostarts...)
	allTrig = append(allTrig, result.Triggerable.Scheduled...)
	allTrig = append(allTrig, result.Triggerable.Keepalive...)
	for _, e := range allTrig {
		hasSuspicious := false
		for _, f := range e.RiskFlags {
			// restart_always alone is not suspicious for cross-state scoring
			if f != "restart_always" && f != "keepalive_enabled" {
				hasSuspicious = true
				break
			}
		}
		triggerablePaths[e.Path] = trigInfo{hasRiskFlags: hasSuspicious}
	}

	// Cross: recently modified persistence that is also triggerable AND has suspicious flags
	for path, info := range changedPaths {
		ti, inTrig := triggerablePaths[path]
		if !inTrig {
			continue
		}
		// Require at least one side to have suspicious flags
		if !info.risky && !ti.hasRiskFlags {
			continue
		}
		addEvidence(sr, "cross_state", RuleCrossRetainedTriggerable,
			fmt.Sprintf("近期变更的持久化项同时具备自动触发能力且存在异常: %s", path),
			8, "medium", map[string]interface{}{"path": path})
	}

	// Cross: retained artifacts that are currently running (via runtime)
	if result.Runtime != nil {
		runningExes := make(map[string]bool)
		for _, p := range result.Runtime.Processes {
			if p.Exe != "" {
				runningExes[p.Exe] = true
			}
		}

		for _, a := range result.Retained.Artifacts {
			if a.Type == "tmp_executable" && runningExes[a.Path] {
				addEvidence(sr, "cross_state", RuleCrossRetainedRuntime,
					fmt.Sprintf("临时目录残留可执行文件当前正在运行: %s", a.Path),
					10, "high", map[string]interface{}{"path": a.Path})
			}
		}

		// Cross: recently changed persistence + currently running + keepalive
		// Only trigger if there's an additional suspicious indicator beyond restart_always
		for _, c := range result.Retained.PersistChanges {
			if c.Target == "" {
				continue
			}
			if !runningExes[c.Target] {
				continue
			}
			// Must have suspicious target (in tmp, missing, etc.)
			hasSuspiciousTarget := false
			for _, f := range c.RiskFlags {
				if f == "target_in_tmp" || f == "target_missing" {
					hasSuspiciousTarget = true
					break
				}
			}
			if !hasSuspiciousTarget {
				continue
			}
			for _, k := range result.Triggerable.Keepalive {
				if k.Path == c.Path || k.Target == c.Target {
					addEvidence(sr, "cross_state", RuleCrossPersistRunningKeepalive,
						fmt.Sprintf("近期变更+目标异常+正在运行+自动重启: %s → %s", c.Path, c.Target),
						10, "high", map[string]interface{}{
							"path":   c.Path,
							"target": c.Target,
						})
					addIntegrityFlag(sr, "cross_state_critical_chain")
					break
				}
			}
		}
	}
}
