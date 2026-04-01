package model

import "time"

// CollectionResult is the top-level envelope containing all forensic data
// from a single LinIR run. This struct defines the JSON output schema.
type CollectionResult struct {
	Version      string `json:"version"`
	ToolName     string `json:"tool_name"`
	CollectionID string `json:"collection_id"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	DurationMS   int64     `json:"duration_ms"`

	Host         HostInfo          `json:"host"`
	Capabilities *Capabilities    `json:"capabilities,omitempty"`
	SelfCheck   SelfCheckResult   `json:"self_check"`
	Preflight   PreflightResult   `json:"preflight"`
	Processes   []ProcessInfo     `json:"processes,omitempty"`
	Connections []ConnectionInfo  `json:"connections,omitempty"`
	Persistence []PersistenceItem `json:"persistence,omitempty"`
	Integrity   *IntegrityResult  `json:"integrity,omitempty"`
	YaraHits    []YaraHit         `json:"yara_hits,omitempty"`
	Score       *ScoreResult      `json:"score,omitempty"`

	Errors []CollectionError `json:"errors,omitempty"`
}

// CollectionError records a non-fatal error encountered during collection.
type CollectionError struct {
	Phase   string `json:"phase"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}
