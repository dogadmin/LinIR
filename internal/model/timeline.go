package model

import "time"

// TimelineEvent represents a single event in the unified forensic timeline.
// Events from all three states (runtime/retained/triggerable) share this structure.
type TimelineEvent struct {
	Time       time.Time              `json:"time"`
	TimeType   string                 `json:"time_type"`              // "actual"|"synthetic"
	SynthLabel string                 `json:"synth_label,omitempty"`  // "next_boot"|"next_login"|"scheduled:..."|"future"
	Scope      string                 `json:"scope"`                  // "runtime"|"retained"|"triggerable"
	Type       string                 `json:"type"`                   // event type key
	Object     string                 `json:"object"`                 // primary identifier (path, PID, service name)
	Severity   string                 `json:"severity"`               // "info"|"low"|"medium"|"high"|"critical"
	Confidence string                 `json:"confidence"`             // "high"|"medium"|"low"
	Source     string                 `json:"source"`                 // data source identifier
	Summary    string                 `json:"summary"`                // human-readable one-line description
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}
