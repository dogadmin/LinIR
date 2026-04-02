//go:build linux

package triggerable

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/sysparse"
)

// collectLinuxScheduled enumerates systemd timers, cron jobs, and at queue.
func collectLinuxScheduled() ([]model.TriggerableEntry, error) {
	var entries []model.TriggerableEntry

	// 1. systemd timers
	entries = append(entries, collectSystemdTimers()...)

	// 2. cron jobs
	entries = append(entries, collectCronScheduled()...)

	return entries, nil
}

func collectSystemdTimers() []model.TriggerableEntry {
	unitDirs := systemdUnitDirs

	var entries []model.TriggerableEntry
	seen := make(map[string]struct{})

	for _, dir := range unitDirs {
		dirEntries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, de := range dirEntries {
			name := de.Name()
			if !strings.HasSuffix(name, ".timer") {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}

			path := filepath.Join(dir, name)
			realPath := path
			if target, err := filepath.EvalSymlinks(path); err == nil {
				realPath = target
			}

			unit, err := sysparse.ParseSystemdUnit(realPath)
			if err != nil {
				continue
			}

			// Determine schedule expression
			schedule := unit.OnCalendar
			if schedule == "" {
				schedule = unit.OnBootSec
			}

			entry := model.TriggerableEntry{
				Type:             "systemd_timer",
				Category:         "scheduled",
				Path:             realPath,
				Target:           strings.TrimSuffix(name, ".timer") + ".service",
				TriggerCondition: "timer",
				Schedule:         schedule,
				NextFire:         "scheduled:" + schedule,
				UserScope:        "system",
				Enabled:          true,
				Confidence:       "high",
				ParsedFields: map[string]string{
					"OnCalendar": unit.OnCalendar,
					"OnBootSec":  unit.OnBootSec,
				},
			}

			entries = append(entries, entry)
		}
	}

	return entries
}

func collectCronScheduled() []model.TriggerableEntry {
	var entries []model.TriggerableEntry

	// System crontab
	entries = append(entries, parseCronForTriggerable("/etc/crontab", true, "system")...)

	// /etc/cron.d/
	if dirEntries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, de := range dirEntries {
			if de.IsDir() {
				continue
			}
			path := filepath.Join("/etc/cron.d", de.Name())
			entries = append(entries, parseCronForTriggerable(path, true, "system")...)
		}
	}

	// cron.daily/hourly/weekly/monthly script directories
	cronDirs := map[string]string{
		"/etc/cron.daily":   "0 6 * * *",
		"/etc/cron.hourly":  "17 * * * *",
		"/etc/cron.weekly":  "47 6 * * 7",
		"/etc/cron.monthly": "52 6 1 * *",
	}
	for dir, defaultSchedule := range cronDirs {
		if dirEntries, err := os.ReadDir(dir); err == nil {
			for _, de := range dirEntries {
				if de.IsDir() {
					continue
				}
				path := filepath.Join(dir, de.Name())
				entries = append(entries, model.TriggerableEntry{
					Type:             "cron",
					Category:         "scheduled",
					Path:             path,
					Target:           path,
					TriggerCondition: "cron_schedule",
					Schedule:         defaultSchedule + " (" + filepath.Base(dir) + ")",
					NextFire:         "scheduled:" + defaultSchedule,
					UserScope:        "system",
					Enabled:          true,
					Confidence:       "medium",
				})
			}
		}
	}

	// User crontabs
	userCronDirs := []string{"/var/spool/cron", "/var/spool/cron/crontabs"}
	for _, dir := range userCronDirs {
		if dirEntries, err := os.ReadDir(dir); err == nil {
			for _, de := range dirEntries {
				if de.IsDir() {
					continue
				}
				path := filepath.Join(dir, de.Name())
				entries = append(entries, parseCronForTriggerable(path, false, "user")...)
			}
		}
	}

	return entries
}
