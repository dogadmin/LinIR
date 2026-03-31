package model

// PersistenceItem represents a single persistence mechanism found on the system.
type PersistenceItem struct {
	Type         string            `json:"type"`       // "systemd"|"cron"|"launchd"|"shell_profile"|"ssh"|"rc_local"|"ld_preload"
	Path         string            `json:"path"`
	Target       string            `json:"target"`
	UserScope    string            `json:"user_scope"` // "system"|"user"
	ParsedFields map[string]string `json:"parsed_fields,omitempty"`
	RiskFlags    []string          `json:"risk_flags,omitempty"`
	Exists       bool              `json:"exists"`
	Confidence   string            `json:"confidence"` // "high"|"medium"|"low"
}
