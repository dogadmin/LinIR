package retained

import (
	"os"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/score"
)

// detectPersistenceChanges examines existing persistence items and flags any
// whose configuration files were modified within the retention window.
func detectPersistenceChanges(items []model.PersistenceItem, window time.Duration) []model.PersistenceChange {
	cutoff := time.Now().Add(-window)
	var changes []model.PersistenceChange

	seen := make(map[string]struct{})
	for _, item := range items {
		if item.Path == "" {
			continue
		}
		// Deduplicate by path (multiple cron entries may share same file)
		if _, ok := seen[item.Path]; ok {
			continue
		}
		seen[item.Path] = struct{}{}

		info, err := os.Stat(item.Path)
		if err != nil {
			// File was listed in persistence but now missing
			changes = append(changes, model.PersistenceChange{
				Type:       item.Type,
				Path:       item.Path,
				Target:     item.Target,
				ChangeType: "missing_target",
				RiskFlags:  []string{"persistence_file_disappeared"},
				Confidence: "medium",
			})
			continue
		}

		modTime := info.ModTime()
		if modTime.Before(cutoff) {
			// Also check ctime (platform-specific)
			ctime := getFileCtime(info)
			if ctime.IsZero() || ctime.Before(cutoff) {
				continue
			}
			// ctime within window but mtime is old = metadata-only change
			changes = append(changes, model.PersistenceChange{
				Type:       item.Type,
				Path:       item.Path,
				Target:     item.Target,
				ModTime:    modTime,
				ChangeTime: ctime,
				ChangeType: "metadata_changed",
				Confidence: "high",
			})
			continue
		}

		change := model.PersistenceChange{
			Type:       item.Type,
			Path:       item.Path,
			Target:     item.Target,
			ModTime:    modTime,
			ChangeType: "modified",
			Confidence: "high",
		}

		// Try to get ctime (platform-specific)
		change.ChangeTime = getFileCtime(info)

		// Risk flags for recently modified persistence
		if item.Target != "" {
			if score.IsInTmpDir(item.Target) {
				change.RiskFlags = append(change.RiskFlags, "target_in_tmp")
			}
			if _, err := os.Stat(item.Target); err != nil {
				change.RiskFlags = append(change.RiskFlags, "target_missing")
			}
		}

		changes = append(changes, change)
	}

	return changes
}
