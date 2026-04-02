package model

import "time"

// TriggerableState enumerates future execution paths — objects that will run
// at next boot, next login, on schedule, or upon service failure without
// further attacker interaction.
type TriggerableState struct {
	CollectedAt time.Time          `json:"collected_at"`
	Autostarts  []TriggerableEntry `json:"autostarts,omitempty"`
	Scheduled   []TriggerableEntry `json:"scheduled,omitempty"`
	Keepalive   []TriggerableEntry `json:"keepalive,omitempty"`
	Confidence  string             `json:"confidence"` // "high"|"medium"|"low"|"unavailable"
}

// TriggerableEntry represents a single future execution path.
type TriggerableEntry struct {
	Type             string            `json:"type"`              // "systemd_enabled"|"systemd_timer"|"cron"|"anacron"|"at"|"launchd"|"rc_local"|"shell_profile"|"ssh_forced_command"|"login_hook"
	Category         string            `json:"category"`          // "autostart"|"scheduled"|"keepalive"
	Path             string            `json:"path"`
	Target           string            `json:"target"`
	TriggerCondition string            `json:"trigger_condition"` // "boot"|"login"|"timer"|"cron_schedule"|"failure"|"always"|"interval"
	Schedule         string            `json:"schedule,omitempty"`
	NextFire         string            `json:"next_fire,omitempty"` // "next_boot"|"next_login"|ISO8601|"scheduled:*/5 * * * *"|"future"
	UserScope        string            `json:"user_scope"`          // "system"|"user"
	Enabled          bool              `json:"enabled"`
	ParsedFields     map[string]string `json:"parsed_fields,omitempty"`
	RiskFlags        []string          `json:"risk_flags,omitempty"`
	Confidence       string            `json:"confidence"`
}
