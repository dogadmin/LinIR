package model

// ConnectionInfo represents a single network connection with forensic context.
// Source indicates the data origin ("procfs", "native_api").
// Confidence indicates how reliably the PID association was resolved.
type ConnectionInfo struct {
	Proto         string `json:"proto"`          // "tcp"|"udp"|"unix"|"raw"
	Family        string `json:"family"`         // "ipv4"|"ipv6"|"unix"
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    uint16 `json:"remote_port"`
	State         string `json:"state"`
	SocketInode   uint64 `json:"socket_inode,omitempty"`
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name,omitempty"`
	SuspiciousFlags []string `json:"suspicious_flags,omitempty"`
	Source          string   `json:"source"`     // "procfs"|"native_api"
	Confidence      string   `json:"confidence"` // "high"|"medium"|"low"
}
