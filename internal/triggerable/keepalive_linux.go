//go:build linux

package triggerable

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/score"
	"github.com/dogadmin/LinIR/pkg/sysparse"
)

// collectLinuxKeepalive finds services with Restart=always/on-failure and
// other self-healing mechanisms.
func collectLinuxKeepalive() ([]model.TriggerableEntry, error) {
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
			if !strings.HasSuffix(name, ".service") {
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

			restart := strings.TrimSpace(unit.Restart)
			if restart == "" || restart == "no" {
				continue
			}

			entry := model.TriggerableEntry{
				Type:     "systemd_enabled",
				Category: "keepalive",
				Path:     realPath,
				Target:   sysparse.ExtractExecTarget(unit.ExecStart),
				UserScope: "system",
				Enabled:  true,
				Confidence: "high",
				ParsedFields: map[string]string{
					"Restart":     restart,
					"ExecStart":   unit.ExecStart,
					"User":        unit.User,
					"WatchdogSec": unit.WatchdogSec,
				},
			}

			switch restart {
			case "always":
				entry.TriggerCondition = "always"
				entry.NextFire = "future"
				entry.RiskFlags = append(entry.RiskFlags, "restart_always")
			case "on-failure":
				entry.TriggerCondition = "failure"
				entry.NextFire = "future"
			case "on-abnormal":
				entry.TriggerCondition = "failure"
				entry.NextFire = "future"
			case "on-abort":
				entry.TriggerCondition = "failure"
				entry.NextFire = "future"
			default:
				entry.TriggerCondition = "failure"
				entry.NextFire = "future"
			}

			if score.IsInTmpDir(entry.Target) {
				entry.RiskFlags = append(entry.RiskFlags, "target_in_tmp")
			}
			if entry.Target != "" {
				if _, err := os.Stat(entry.Target); err != nil {
					entry.RiskFlags = append(entry.RiskFlags, "target_missing")
				}
			}

			entries = append(entries, entry)
		}
	}

	// SSH forced commands as keepalive-like mechanism
	entries = append(entries, collectSSHForcedCommands()...)

	return entries, nil
}

func collectSSHForcedCommands() []model.TriggerableEntry {
	var entries []model.TriggerableEntry

	authKeyPaths := []string{"/root/.ssh/authorized_keys"}

	// User homes
	if dirEntries, err := os.ReadDir("/home"); err == nil {
		for _, de := range dirEntries {
			if de.IsDir() {
				authKeyPaths = append(authKeyPaths, filepath.Join("/home", de.Name(), ".ssh", "authorized_keys"))
			}
		}
	}

	for _, path := range authKeyPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !strings.HasPrefix(line, "command=") && !strings.Contains(line, ",command=") {
				continue
			}
			// Extract the forced command
			cmd := extractForcedCommand(line)
			if cmd == "" {
				continue
			}
			entries = append(entries, model.TriggerableEntry{
				Type:             "ssh_forced_command",
				Category:         "keepalive",
				Path:             path,
				Target:           cmd,
				TriggerCondition: "login",
				NextFire:         "next_login",
				UserScope:        "user",
				Enabled:          true,
				Confidence:       "high",
				ParsedFields: map[string]string{
					"forced_command": cmd,
				},
			})
		}
	}

	return entries
}

func extractForcedCommand(line string) string {
	// Format: command="xxx" ssh-rsa ...  or  ...,command="xxx",... ssh-rsa ...
	idx := strings.Index(line, "command=\"")
	if idx < 0 {
		return ""
	}
	rest := line[idx+len("command=\""):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return ""
	}
	return rest[:end]
}
