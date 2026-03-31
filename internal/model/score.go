package model

// ScoreResult is the overall triage risk assessment.
type ScoreResult struct {
	Total      int        `json:"total"`
	Severity   string     `json:"severity"`   // "info"|"low"|"medium"|"high"|"critical"
	Confidence string     `json:"confidence"` // "high"|"medium"|"low"
	Evidence   []Evidence `json:"evidence"`
	Summary    string     `json:"summary"`
}

// Evidence is a single scored observation contributing to the overall score.
type Evidence struct {
	Domain      string                 `json:"domain"` // "process"|"network"|"persistence"|"integrity"|"yara"
	Rule        string                 `json:"rule"`
	Description string                 `json:"description"`
	Score       int                    `json:"score"`
	Severity    string                 `json:"severity"`
	Details     map[string]interface{} `json:"details,omitempty"`
}
