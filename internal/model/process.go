package model

// ProcessInfo represents a single running process with forensic-relevant fields.
// Source indicates where the data was obtained ("procfs", "native_api").
// Confidence indicates the reliability of this entry ("high", "medium", "low").
type ProcessInfo struct {
	PID             int               `json:"pid"`
	PPID            int               `json:"ppid"`
	Name            string            `json:"name"`
	Exe             string            `json:"exe"`
	Cmdline         []string          `json:"cmdline"`
	Cwd             string            `json:"cwd"`
	UID             int               `json:"uid"`
	GID             int               `json:"gid"`
	Username        string            `json:"username"`
	StartTime       string            `json:"start_time"`
	EnvironSample   map[string]string `json:"environ_sample,omitempty"`
	FDCount         int               `json:"fd_count"`
	SocketInodes    []uint64          `json:"socket_inodes,omitempty"`
	MapsSummary     []string          `json:"maps_summary,omitempty"`
	SuspiciousFlags []string          `json:"suspicious_flags,omitempty"`
	Source          string            `json:"source"`     // "procfs"|"native_api"
	Confidence      string            `json:"confidence"` // "high"|"medium"|"low"
}
