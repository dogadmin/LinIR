package model

import "time"

// AnalysisResult is the top-level envelope for three-dimensional forensic analysis.
// It wraps a CollectionResult as the Runtime state and adds Retained,
// Triggerable, and Timeline dimensions.
type AnalysisResult struct {
	Version      string    `json:"version"`
	ToolName     string    `json:"tool_name"`
	AnalysisID   string    `json:"analysis_id"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	DurationMS   int64     `json:"duration_ms"`

	Host         HostInfo          `json:"host"`
	Capabilities *Capabilities     `json:"capabilities,omitempty"`

	Runtime     *CollectionResult  `json:"runtime,omitempty"`
	Retained    *RetainedState     `json:"retained,omitempty"`
	Triggerable *TriggerableState  `json:"triggerable,omitempty"`
	Timeline    []TimelineEvent    `json:"timeline,omitempty"`

	Confidence AnalysisConfidence  `json:"confidence"`
	Errors     []CollectionError   `json:"errors,omitempty"`
}

// AnalysisConfidence tracks per-dimension confidence levels.
type AnalysisConfidence struct {
	Runtime     string `json:"runtime"`     // "high"|"medium"|"low"|"unavailable"
	Retained    string `json:"retained"`    // "high"|"medium"|"low"|"unavailable"
	Triggerable string `json:"triggerable"` // "high"|"medium"|"low"|"unavailable"
	Overall     string `json:"overall"`
}
