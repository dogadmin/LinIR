package model

// YaraHit represents a single YARA rule match against a target.
type YaraHit struct {
	Rule         string            `json:"rule"`
	TargetType   string            `json:"target_type"` // "file"|"process-linked-file"|"persistence-target"
	TargetPath   string            `json:"target_path"`
	Meta         map[string]string `json:"meta,omitempty"`
	Strings      []string          `json:"strings,omitempty"`
	SeverityHint string            `json:"severity_hint"`
	LinkedPID    int               `json:"linked_pid,omitempty"`
}
