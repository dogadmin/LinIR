package timeline

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// Build merges events from Runtime, Retained, and Triggerable states into a
// unified, sorted timeline. Actual-time events sort chronologically;
// synthetic-time events appear at the end ordered by priority.
func Build(runtime *model.CollectionResult, retained *model.RetainedState, triggerable *model.TriggerableState) []model.TimelineEvent {
	var events []model.TimelineEvent

	if runtime != nil {
		events = append(events, runtimeEvents(runtime)...)
	}
	if retained != nil {
		events = append(events, retainedEvents(retained)...)
	}
	if triggerable != nil {
		events = append(events, triggerableEvents(triggerable)...)
	}

	sortEvents(events)
	return events
}

// ========== Runtime → Timeline ==========

func runtimeEvents(r *model.CollectionResult) []model.TimelineEvent {
	var events []model.TimelineEvent
	collectionTime := r.StartedAt

	// Processes (only suspicious ones to reduce noise)
	for _, p := range r.Processes {
		if len(p.SuspiciousFlags) == 0 {
			continue
		}
		t := collectionTime
		if p.StartTime != "" {
			if parsed, err := time.Parse("2006-01-02 15:04:05", p.StartTime); err == nil {
				t = parsed
			}
		}

		severity := "info"
		if len(p.SuspiciousFlags) > 0 {
			severity = "low"
			for _, f := range p.SuspiciousFlags {
				if f == "webserver_spawned_shell" || f == "fake_kernel_thread" {
					severity = "high"
					break
				}
				if f == "exe_in_tmp" || f == "exe_deleted" || f == "persistent_and_networked" {
					severity = "medium"
				}
			}
		}

		events = append(events, model.TimelineEvent{
			Time:       t,
			TimeType:   "actual",
			Scope:      "runtime",
			Type:       "process_active",
			Object:     p.Exe,
			Severity:   severity,
			Confidence: p.Confidence,
			Source:     p.Source,
			Summary:    fmt.Sprintf("PID %d (%s) %s", p.PID, p.Name, strings.Join(p.SuspiciousFlags, ", ")),
		})
	}

	// Active connections with suspicious flags
	for _, c := range r.Connections {
		if len(c.SuspiciousFlags) == 0 && c.State != "ESTABLISHED" {
			continue
		}
		events = append(events, model.TimelineEvent{
			Time:       collectionTime,
			TimeType:   "actual",
			Scope:      "runtime",
			Type:       "connection_active",
			Object:     fmt.Sprintf("%s:%d→%s:%d", c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort),
			Severity:   connectionSeverity(c),
			Confidence: c.Confidence,
			Source:     c.Source,
			Summary:    fmt.Sprintf("%s %s PID=%d %s", c.Proto, c.State, c.PID, strings.Join(c.SuspiciousFlags, ", ")),
		})
	}

	// YARA hits
	for _, y := range r.YaraHits {
		sev := "medium"
		if y.SeverityHint != "" {
			sev = y.SeverityHint
		}
		events = append(events, model.TimelineEvent{
			Time:       collectionTime,
			TimeType:   "actual",
			Scope:      "runtime",
			Type:       "yara_hit",
			Object:     y.TargetPath,
			Severity:   sev,
			Confidence: "high",
			Source:     "yara",
			Summary:    fmt.Sprintf("YARA 规则 %s 命中 %s", y.Rule, y.TargetPath),
		})
	}

	// Active persistence with risk flags
	for _, p := range r.Persistence {
		if len(p.RiskFlags) == 0 {
			continue
		}
		events = append(events, model.TimelineEvent{
			Time:       collectionTime,
			TimeType:   "actual",
			Scope:      "runtime",
			Type:       "persistence_active",
			Object:     p.Path,
			Severity:   persistenceSeverity(p),
			Confidence: p.Confidence,
			Source:     "filesystem",
			Summary:    fmt.Sprintf("%s %s → %s [%s]", p.Type, p.Path, p.Target, strings.Join(p.RiskFlags, ", ")),
		})
	}

	return events
}

// ========== Retained → Timeline ==========

func retainedEvents(r *model.RetainedState) []model.TimelineEvent {
	var events []model.TimelineEvent

	// File timeline
	for _, f := range r.FileTimeline {
		severity := "info"
		if len(f.RiskFlags) > 0 {
			severity = "low"
			for _, flag := range f.RiskFlags {
				if flag == "executable_in_tmp" || flag == "setuid" {
					severity = "medium"
					break
				}
			}
		}
		events = append(events, model.TimelineEvent{
			Time:       f.ModTime,
			TimeType:   "actual",
			Scope:      "retained",
			Type:       "file_modified",
			Object:     f.Path,
			Severity:   severity,
			Confidence: f.Confidence,
			Source:     "filesystem",
			Summary:    fmt.Sprintf("文件变更 %s (in %s)", f.Path, f.KeyDir),
		})
	}

	// Persistence changes
	for _, c := range r.PersistChanges {
		severity := "medium"
		if len(c.RiskFlags) > 0 {
			severity = "high"
		}
		events = append(events, model.TimelineEvent{
			Time:       c.ModTime,
			TimeType:   "actual",
			Scope:      "retained",
			Type:       "persistence_changed",
			Object:     c.Path,
			Severity:   severity,
			Confidence: c.Confidence,
			Source:     "filesystem",
			Summary:    fmt.Sprintf("持久化 %s %s: %s → %s", c.ChangeType, c.Type, c.Path, c.Target),
		})
	}

	// Artifacts (use collection time, not wall clock)
	for _, a := range r.Artifacts {
		severity := "medium"
		if a.Type == "deleted_exe" {
			severity = "high"
		}
		events = append(events, model.TimelineEvent{
			Time:       r.CollectedAt,
			TimeType:   "synthetic",
			SynthLabel: "discovery_time",
			Scope:      "retained",
			Type:       "artifact_" + a.Type,
			Object:     a.Path,
			Severity:   severity,
			Confidence: a.Confidence,
			Source:     a.Source,
			Summary:    a.Reason,
		})
	}

	// Auth history
	for _, a := range r.AuthHistory {
		severity := "info"
		if !a.Success {
			severity = "low"
		}
		if a.Type == "sudo" || a.Type == "su" {
			severity = "low"
		}
		events = append(events, model.TimelineEvent{
			Time:       a.Time,
			TimeType:   "actual",
			Scope:      "retained",
			Type:       "auth_" + a.Type,
			Object:     a.User,
			Severity:   severity,
			Confidence: "medium",
			Source:     a.Source,
			Summary:    fmt.Sprintf("%s %s from %s", a.Type, a.User, a.RemoteIP),
		})
	}

	return events
}

// ========== Triggerable → Timeline ==========

func triggerableEvents(t *model.TriggerableState) []model.TimelineEvent {
	var events []model.TimelineEvent

	addEntries := func(entries []model.TriggerableEntry) {
		for _, e := range entries {
			severity := "info"
			if len(e.RiskFlags) > 0 {
				severity = "low"
				for _, f := range e.RiskFlags {
					if f == "target_in_tmp" || f == "restart_always" || f == "pipe_to_shell" || f == "dev_tcp_reverse_shell" {
						severity = "medium"
						break
					}
				}
			}

			nextFire := e.NextFire
			if nextFire == "" {
				nextFire = "future"
			}

			events = append(events, model.TimelineEvent{
				Time:       syntheticBase,
				TimeType:   "synthetic",
				SynthLabel: nextFire,
				Scope:      "triggerable",
				Type:       "triggerable_" + e.Category,
				Object:     e.Path,
				Severity:   severity,
				Confidence: e.Confidence,
				Source:     e.Type,
				Summary:    fmt.Sprintf("[%s] %s → %s (%s)", e.Category, e.Path, e.Target, e.TriggerCondition),
			})
		}
	}

	addEntries(t.Autostarts)
	addEntries(t.Scheduled)
	addEntries(t.Keepalive)

	return events
}

// ========== Helpers ==========

func connectionSeverity(c model.ConnectionInfo) string {
	for _, f := range c.SuspiciousFlags {
		if strings.HasPrefix(f, "suspicious_remote_port") {
			return "low"
		}
		if f == "orphan_active_connection" {
			return "medium"
		}
	}
	return "info"
}

func persistenceSeverity(p model.PersistenceItem) string {
	for _, f := range p.RiskFlags {
		switch f {
		case "dev_tcp_reverse_shell":
			return "critical"
		case "target_in_tmp", "system_wide_preload", "ld_preload_in_env", "ld_preload_export", "dyld_inject_export":
			return "high"
		case "target_running_with_network", "target_currently_running":
			return "medium"
		}
	}
	return "low"
}

func sortEvents(events []model.TimelineEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		// Actual times sort before synthetic times
		if events[i].TimeType != events[j].TimeType {
			return events[i].TimeType == "actual"
		}
		if events[i].TimeType == "actual" {
			return events[i].Time.Before(events[j].Time)
		}
		// Synthetic: order by label priority
		return synthPriority(events[i].SynthLabel) < synthPriority(events[j].SynthLabel)
	})
}

func synthPriority(label string) int {
	switch label {
	case "next_boot":
		return 0
	case "next_login":
		return 1
	case "future":
		return 3
	default:
		// "scheduled:..." sorts between next_login and future
		return 2
	}
}
