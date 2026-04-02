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

// collectLinuxAutostarts enumerates services/units that will execute at boot or login.
func collectLinuxAutostarts() ([]model.TriggerableEntry, error) {
	var entries []model.TriggerableEntry

	// 1. Enabled systemd units (symlinks in *.wants/ directories)
	entries = append(entries, collectEnabledSystemdUnits()...)

	// 2. rc.local
	entries = append(entries, collectRcLocalAutostart()...)

	// 3. Shell login profiles with active content
	entries = append(entries, collectShellLoginAutostarts()...)

	return entries, nil
}

func collectEnabledSystemdUnits() []model.TriggerableEntry {
	// Enabled units are determined by symlinks in wants/ directories
	wantsDirs := []string{
		"/etc/systemd/system/multi-user.target.wants",
		"/etc/systemd/system/default.target.wants",
		"/etc/systemd/system/graphical.target.wants",
		"/etc/systemd/system/sysinit.target.wants",
	}

	var entries []model.TriggerableEntry
	seen := make(map[string]struct{})

	for _, dir := range wantsDirs {
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

			entry := model.TriggerableEntry{
				Type:             "systemd_enabled",
				Category:         "autostart",
				Path:             realPath,
				TriggerCondition: "boot",
				NextFire:         "next_boot",
				UserScope:        "system",
				Enabled:          true,
				Confidence:       "high",
			}

			// Parse unit for ExecStart target
			unit, err := sysparse.ParseSystemdUnit(realPath)
			if err == nil {
				entry.Target = sysparse.ExtractExecTarget(unit.ExecStart)
				entry.ParsedFields = map[string]string{
					"ExecStart": unit.ExecStart,
					"User":      unit.User,
					"Type":      unit.Type,
					"WantedBy":  unit.WantedBy,
				}
				flagAutostartRisks(&entry, unit)
			}

			entries = append(entries, entry)
		}
	}

	return entries
}

func collectRcLocalAutostart() []model.TriggerableEntry {
	path := "/etc/rc.local"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Check executable permission
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if info.Mode().Perm()&0111 == 0 {
		return nil
	}

	// Check for actual content
	hasContent := false
	var firstCmd string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "exit 0" {
			continue
		}
		hasContent = true
		firstCmd = line
		break
	}
	if !hasContent {
		return nil
	}

	return []model.TriggerableEntry{{
		Type:             "rc_local",
		Category:         "autostart",
		Path:             path,
		Target:           firstCmd,
		TriggerCondition: "boot",
		NextFire:         "next_boot",
		UserScope:        "system",
		Enabled:          true,
		Confidence:       "high",
	}}
}

func collectShellLoginAutostarts() []model.TriggerableEntry {
	// System-wide login profiles
	profiles := []string{
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/bashrc",
		"/etc/zshrc",
		"/etc/zshenv",
	}

	// Add profile.d scripts
	if entries, err := os.ReadDir("/etc/profile.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				profiles = append(profiles, filepath.Join("/etc/profile.d", e.Name()))
			}
		}
	}

	var entries []model.TriggerableEntry
	for _, path := range profiles {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		entries = append(entries, model.TriggerableEntry{
			Type:             "shell_profile",
			Category:         "autostart",
			Path:             path,
			TriggerCondition: "login",
			NextFire:         "next_login",
			UserScope:        "system",
			Enabled:          true,
			Confidence:       "high",
		})
	}

	return entries
}

func flagAutostartRisks(entry *model.TriggerableEntry, unit *sysparse.SystemdUnit) {
	target := entry.Target
	if score.IsInTmpDir(target) {
		entry.RiskFlags = append(entry.RiskFlags, "target_in_tmp")
	}
	if target != "" {
		if _, err := os.Stat(target); err != nil {
			entry.RiskFlags = append(entry.RiskFlags, "target_missing")
		}
	}
	if strings.Contains(unit.Environment, "LD_PRELOAD") {
		entry.RiskFlags = append(entry.RiskFlags, "ld_preload_in_env")
	}
}
