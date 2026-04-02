//go:build darwin

package triggerable

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/plistutil"
)

// collectDarwinScheduled enumerates launchd items with StartInterval or
// StartCalendarInterval, plus any cron jobs.
func collectDarwinScheduled() ([]model.TriggerableEntry, error) {
	var entries []model.TriggerableEntry

	// 1. launchd scheduled items
	entries = append(entries, collectLaunchdScheduled()...)

	// 2. cron (if present on macOS)
	entries = append(entries, collectDarwinCron()...)

	return entries, nil
}

func collectLaunchdScheduled() []model.TriggerableEntry {
	dirs := []struct {
		path  string
		scope string
	}{
		{"/Library/LaunchDaemons", "system"},
		{"/Library/LaunchAgents", "system"},
	}

	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, struct {
			path  string
			scope string
		}{filepath.Join(home, "Library", "LaunchAgents"), "user"})
	}

	var entries []model.TriggerableEntry
	for _, dir := range dirs {
		dirEntries, err := os.ReadDir(dir.path)
		if err != nil {
			continue
		}
		for _, de := range dirEntries {
			if de.IsDir() || !strings.HasSuffix(de.Name(), ".plist") {
				continue
			}
			path := filepath.Join(dir.path, de.Name())
			plist, err := plistutil.ParseLaunchPlist(path)
			if err != nil {
				continue
			}

			// Check for interval-based scheduling
			hasCalendar := plist.StartCalendarInterval != nil
			if plist.StartInterval <= 0 && !hasCalendar {
				continue
			}

			command := plistutil.GetCommand(plist)
			schedule := ""
			if plist.StartInterval > 0 {
				schedule = fmt.Sprintf("every %ds", plist.StartInterval)
			} else if hasCalendar {
				schedule = fmt.Sprintf("calendar: %v", plist.StartCalendarInterval)
			}

			entries = append(entries, model.TriggerableEntry{
				Type:             "launchd",
				Category:         "scheduled",
				Path:             path,
				Target:           command,
				TriggerCondition: "interval",
				Schedule:         schedule,
				NextFire:         "scheduled:" + schedule,
				UserScope:        dir.scope,
				Enabled:          !plist.Disabled,
				Confidence:       "high",
				ParsedFields: map[string]string{
					"Label":         plist.Label,
					"StartInterval": fmt.Sprintf("%d", plist.StartInterval),
				},
			})
		}
	}
	return entries
}

func collectDarwinCron() []model.TriggerableEntry {
	// macOS may have cron installed
	var entries []model.TriggerableEntry

	// System crontab
	if _, err := os.Stat("/etc/crontab"); err == nil {
		entries = append(entries, parseCronForTriggerable("/etc/crontab", true, "system")...)
	}

	// User crontabs
	if dirEntries, err := os.ReadDir("/var/at/tabs"); err == nil {
		for _, de := range dirEntries {
			if de.IsDir() {
				continue
			}
			path := filepath.Join("/var/at/tabs", de.Name())
			entries = append(entries, parseCronForTriggerable(path, false, "user")...)
		}
	}

	return entries
}
