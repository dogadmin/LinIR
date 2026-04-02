package model

import "time"

// RetainedState contains historical forensic traces — evidence of past activity
// recovered from filesystem metadata, logs, and artifact residue.
type RetainedState struct {
	CollectedAt    time.Time           `json:"collected_at"`
	Window         string              `json:"window"` // e.g. "72h"
	FileTimeline   []RetainedFileEntry `json:"file_timeline,omitempty"`
	PersistChanges []PersistenceChange `json:"persistence_changes,omitempty"`
	Artifacts      []ArtifactFinding   `json:"artifacts,omitempty"`
	AuthHistory    []AuthEvent         `json:"auth_history,omitempty"`
	LogEvents      []LogEvent          `json:"log_events,omitempty"`
	Confidence     string              `json:"confidence"` // "high"|"medium"|"low"|"unavailable"
}

// RetainedFileEntry records a file found in a key directory within the retention window.
type RetainedFileEntry struct {
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`
	UID        int       `json:"uid"`
	GID        int       `json:"gid"`
	Owner      string    `json:"owner,omitempty"`
	ModTime    time.Time `json:"mod_time"`
	ChangeTime time.Time `json:"change_time,omitempty"` // ctime, Linux only
	Executable bool      `json:"executable"`
	KeyDir     string    `json:"key_dir"` // which key directory this belongs to
	Hash       string    `json:"hash,omitempty"`
	RiskFlags  []string  `json:"risk_flags,omitempty"`
	Confidence string    `json:"confidence"`
}

// PersistenceChange records a persistence mechanism file that was recently
// created or modified within the retention window.
type PersistenceChange struct {
	Type       string    `json:"type"`       // persistence type (systemd, cron, etc.)
	Path       string    `json:"path"`
	Target     string    `json:"target"`
	ModTime    time.Time `json:"mod_time"`
	ChangeTime time.Time `json:"change_time,omitempty"`
	ChangeType string    `json:"change_type"` // "created"|"modified"|"missing_target"
	RiskFlags  []string  `json:"risk_flags,omitempty"`
	Confidence string    `json:"confidence"`
}

// ArtifactFinding records a forensic artifact residue — evidence of past activity
// that may no longer be fully present on the system.
type ArtifactFinding struct {
	Type       string            `json:"type"`                  // "deleted_exe"|"maps_missing"|"persist_target_missing"|"tmp_executable"
	Path       string            `json:"path"`
	LinkedPID  int               `json:"linked_pid,omitempty"`
	LinkedItem string            `json:"linked_item,omitempty"` // e.g. persistence path
	Reason     string            `json:"reason"`
	Source     string            `json:"source"` // "procfs"|"filesystem"
	Confidence string            `json:"confidence"`
	Details    map[string]string `json:"details,omitempty"`
}

// AuthEvent records an authentication-related event recovered from system logs.
type AuthEvent struct {
	Time     time.Time         `json:"time"`
	Type     string            `json:"type"` // "login"|"logout"|"failed_login"|"sudo"|"su"|"ssh_accept"|"ssh_reject"
	User     string            `json:"user"`
	Source   string            `json:"source"` // "wtmp"|"btmp"|"lastlog"|"auth.log"|"secure"
	RemoteIP string            `json:"remote_ip,omitempty"`
	Terminal string            `json:"terminal,omitempty"`
	Success  bool              `json:"success"`
	Details  map[string]string `json:"details,omitempty"`
}

// LogEvent records a log entry extracted within a time window.
type LogEvent struct {
	Time     time.Time `json:"time"`
	Facility string    `json:"facility,omitempty"` // "auth"|"daemon"|"kern"
	Severity string    `json:"severity,omitempty"` // syslog severity
	Process  string    `json:"process,omitempty"`
	Message  string    `json:"message"`
	Source   string    `json:"source"` // "journal"|"syslog"|"auth.log"|"unified_log"
}
