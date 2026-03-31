package persistence

import (
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// Analyze 对采集后的持久化项做二次分析。
// 设计原则：只标记真正需要安全人员关注的异常。
// 正常运维行为（cron 联网、systemd 用 bash、output 重定向）不标记。
func Analyze(items []model.PersistenceItem) {
	for i := range items {
		analyzePersistenceItem(&items[i])
	}
}

func analyzePersistenceItem(item *model.PersistenceItem) {
	if item.Type == "systemd" {
		analyzeSystemdItem(item)
	}
}

func analyzeSystemdItem(item *model.PersistenceItem) {
	execStart := item.ParsedFields["ExecStart"]
	if execStart == "" {
		return
	}

	// 只标记明确可疑的 systemd 模式
	// curl/wget 管道到 shell 执行——即使在 systemd 中也可疑
	if (strings.Contains(execStart, "curl ") || strings.Contains(execStart, "wget ")) &&
		(strings.Contains(execStart, "| bash") || strings.Contains(execStart, "| sh")) {
		addRiskFlag(item, "pipe_to_shell")
	}

	// /dev/tcp 反弹 shell
	if strings.Contains(execStart, "/dev/tcp/") {
		addRiskFlag(item, "dev_tcp_reverse_shell")
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
