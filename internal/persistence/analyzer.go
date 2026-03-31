package persistence

import (
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// Analyze 对采集后的持久化项进行二次分析，补充风险标记。
func Analyze(items []model.PersistenceItem) {
	if len(items) == 0 {
		return
	}

	for i := range items {
		analyzePersistenceItem(&items[i])
	}
}

func analyzePersistenceItem(item *model.PersistenceItem) {
	target := item.Target

	// 目标使用了解释器执行
	interpreters := []string{
		"/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby",
		"/usr/bin/php", "/usr/bin/node", "/usr/bin/lua",
		"/bin/python", "/bin/perl",
	}
	for _, interp := range interpreters {
		if strings.HasPrefix(target, interp) {
			addRiskFlag(item, "interpreter_target")
			break
		}
	}

	// 对 systemd 类型做额外检查
	if item.Type == "systemd" {
		analyzeSystemdItem(item)
	}

	// 对 cron 类型做额外检查
	if item.Type == "cron" {
		analyzeCronItem(item)
	}

	// 对 ld_preload 类型——已在采集阶段全面标记
	// 对 ssh 类型——已在采集阶段标记权限和 forced_command
}

func analyzeSystemdItem(item *model.PersistenceItem) {
	execStart := item.ParsedFields["ExecStart"]

	// ExecStart 使用了网络下载
	if strings.Contains(execStart, "curl ") || strings.Contains(execStart, "wget ") {
		addRiskFlag(item, "downloads_from_network")
	}

	// ExecStart 包含 base64
	if strings.Contains(execStart, "base64") {
		addRiskFlag(item, "base64_usage")
	}

	// ExecStart 使用管道到 shell
	if strings.Contains(execStart, "| bash") || strings.Contains(execStart, "| sh") {
		addRiskFlag(item, "pipe_to_shell")
	}

	// Type=simple 或 Type=oneshot 且无 WantedBy = 可能是孤立 service
	unitType := item.ParsedFields["Type"]
	wantedBy := item.ParsedFields["WantedBy"]
	if (unitType == "simple" || unitType == "oneshot") && wantedBy == "" {
		addRiskFlag(item, "orphan_service")
	}
}

func analyzeCronItem(item *model.PersistenceItem) {
	command := item.ParsedFields["command"]
	if command == "" {
		return
	}

	// 命令使用了编码/混淆
	if strings.Contains(command, "\\x") || strings.Contains(command, "$'\\") {
		addRiskFlag(item, "encoded_command")
	}

	// 命令输出被重定向到 /dev/null（隐藏输出）
	if strings.Contains(command, "> /dev/null") || strings.Contains(command, ">/dev/null") {
		if strings.Contains(command, "2>&1") || strings.Contains(command, "&>/dev/null") {
			addRiskFlag(item, "output_suppressed")
		}
	}

	// 命令使用了 nohup（持久化意图）
	if strings.Contains(command, "nohup ") {
		addRiskFlag(item, "nohup_usage")
	}
}

func addRiskFlag(item *model.PersistenceItem, flag string) {
	for _, f := range item.RiskFlags {
		if f == flag {
			return
		}
	}
	item.RiskFlags = append(item.RiskFlags, flag)
}
