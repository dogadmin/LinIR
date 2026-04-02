package triggerable

import (
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/score"
	"github.com/dogadmin/LinIR/pkg/sysparse"
)

// parseCronForTriggerable parses a crontab file and returns triggerable entries.
// Shared between Linux and macOS.
func parseCronForTriggerable(path string, systemFormat bool, scope string) []model.TriggerableEntry {
	cronEntries, err := sysparse.ParseCrontab(path, systemFormat)
	if err != nil || len(cronEntries) == 0 {
		return nil
	}

	var entries []model.TriggerableEntry
	for _, ce := range cronEntries {
		schedule := strings.Join([]string{ce.Minute, ce.Hour, ce.Day, ce.Month, ce.Weekday}, " ")
		target := sysparse.ExtractCronCommand(ce.Command)

		entry := model.TriggerableEntry{
			Type:             "cron",
			Category:         "scheduled",
			Path:             path,
			Target:           target,
			TriggerCondition: "cron_schedule",
			Schedule:         schedule,
			NextFire:         "scheduled:" + schedule,
			UserScope:        scope,
			Enabled:          true,
			Confidence:       "high",
			ParsedFields: map[string]string{
				"command": ce.Command,
				"user":    ce.User,
			},
		}

		// Risk flags
		if score.IsInTmpDir(target) {
			entry.RiskFlags = append(entry.RiskFlags, "target_in_tmp")
		}
		if strings.Contains(ce.Command, "/dev/tcp/") {
			entry.RiskFlags = append(entry.RiskFlags, "dev_tcp_reverse_shell")
		}
		if (strings.Contains(ce.Command, "curl ") || strings.Contains(ce.Command, "wget ")) &&
			(strings.Contains(ce.Command, "| bash") || strings.Contains(ce.Command, "| sh") ||
				strings.Contains(ce.Command, "|bash") || strings.Contains(ce.Command, "|sh")) {
			entry.RiskFlags = append(entry.RiskFlags, "pipe_to_shell")
		}

		entries = append(entries, entry)
	}
	return entries
}

