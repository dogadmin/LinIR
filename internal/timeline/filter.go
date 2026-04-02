package timeline

import (
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// FilterByScope returns events matching the given scope ("runtime", "retained", "triggerable").
func FilterByScope(events []model.TimelineEvent, scope string) []model.TimelineEvent {
	var out []model.TimelineEvent
	for _, e := range events {
		if e.Scope == scope {
			out = append(out, e)
		}
	}
	return out
}

// FilterBySeverity returns events at or above the given severity level.
func FilterBySeverity(events []model.TimelineEvent, minSeverity string) []model.TimelineEvent {
	minRank := severityRank(minSeverity)
	var out []model.TimelineEvent
	for _, e := range events {
		if severityRank(e.Severity) >= minRank {
			out = append(out, e)
		}
	}
	return out
}

// FilterByTimeWindow returns actual-time events within the given window.
// Synthetic events are always included.
func FilterByTimeWindow(events []model.TimelineEvent, start, end time.Time) []model.TimelineEvent {
	var out []model.TimelineEvent
	for _, e := range events {
		if e.TimeType == "synthetic" {
			out = append(out, e)
			continue
		}
		if !e.Time.Before(start) && !e.Time.After(end) {
			out = append(out, e)
		}
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default: // "info"
		return 0
	}
}
