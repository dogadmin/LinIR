//go:build darwin

package triggerable

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/score"
	"github.com/dogadmin/LinIR/pkg/plistutil"
)

// collectDarwinAutostarts enumerates LaunchAgents/Daemons with RunAtLoad=true
// and shell login profiles.
func collectDarwinAutostarts() ([]model.TriggerableEntry, error) {
	var entries []model.TriggerableEntry

	// 1. LaunchDaemons/Agents with RunAtLoad
	entries = append(entries, collectRunAtLoadItems()...)

	// 2. Shell login profiles
	entries = append(entries, collectDarwinShellProfiles()...)

	return entries, nil
}

func collectRunAtLoadItems() []model.TriggerableEntry {
	dirs := []struct {
		path  string
		scope string
	}{
		{"/Library/LaunchDaemons", "system"},
		{"/Library/LaunchAgents", "system"},
	}

	// User LaunchAgents
	userDirs, _ := os.ReadDir("/Users")
	for _, ud := range userDirs {
		if !ud.IsDir() || ud.Name() == "Shared" {
			continue
		}
		dirs = append(dirs, struct {
			path  string
			scope string
		}{filepath.Join("/Users", ud.Name(), "Library", "LaunchAgents"), "user"})
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
			if !plist.RunAtLoad {
				continue
			}

			command := plistutil.GetCommand(plist)
			entry := model.TriggerableEntry{
				Type:             "launchd",
				Category:         "autostart",
				Path:             path,
				Target:           command,
				TriggerCondition: "boot",
				NextFire:         "next_boot",
				UserScope:        dir.scope,
				Enabled:          !plist.Disabled,
				Confidence:       "high",
				ParsedFields: map[string]string{
					"Label":      plist.Label,
					"RunAtLoad":  "true",
				},
			}

			if score.IsInTmpDir(command) {
				entry.RiskFlags = append(entry.RiskFlags, "target_in_tmp")
			}
			if command != "" {
				if _, err := os.Stat(command); err != nil {
					entry.RiskFlags = append(entry.RiskFlags, "target_missing")
				}
			}
			if dir.scope == "user" && strings.HasPrefix(plist.Label, "com.apple.") {
				entry.RiskFlags = append(entry.RiskFlags, "impersonates_apple")
			}

			entries = append(entries, entry)
		}
	}

	return entries
}

func collectDarwinShellProfiles() []model.TriggerableEntry {
	profiles := []string{
		"/etc/profile",
		"/etc/bashrc",
		"/etc/zshrc",
		"/etc/zprofile",
		"/etc/zshenv",
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
