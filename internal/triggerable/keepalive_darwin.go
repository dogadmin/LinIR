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

// collectDarwinKeepalive finds LaunchAgents/Daemons with KeepAlive=true
// or other restart-on-failure mechanisms.
func collectDarwinKeepalive() ([]model.TriggerableEntry, error) {
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

			if !isKeepAlive(plist.KeepAlive) {
				continue
			}

			command := plistutil.GetCommand(plist)
			entry := model.TriggerableEntry{
				Type:             "launchd",
				Category:         "keepalive",
				Path:             path,
				Target:           command,
				TriggerCondition: "always",
				NextFire:         "future",
				UserScope:        dir.scope,
				Enabled:          !plist.Disabled,
				Confidence:       "high",
				ParsedFields: map[string]string{
					"Label":     plist.Label,
					"KeepAlive": "true",
				},
				RiskFlags: []string{"keepalive_enabled"},
			}

			if score.IsInTmpDir(command) {
				entry.RiskFlags = append(entry.RiskFlags, "target_in_tmp")
			}
			if command != "" {
				if _, err := os.Stat(command); err != nil {
					entry.RiskFlags = append(entry.RiskFlags, "target_missing")
				}
			}

			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// isKeepAlive checks the KeepAlive plist value which can be a bool or a dict.
// If it's a dict, KeepAlive is considered true (it has conditions).
func isKeepAlive(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case map[string]interface{}:
		return len(val) > 0
	default:
		return v != nil
	}
}
