package model

import "time"

// HostInfo captures the identity and configuration of the target system.
type HostInfo struct {
	Hostname         string            `json:"hostname"`
	Platform         string            `json:"platform"`                    // "linux" | "macos"
	KernelVersion    string            `json:"kernel_version"`
	Arch             string            `json:"arch"`
	UptimeSeconds    int64             `json:"uptime_seconds"`
	Containerized    bool              `json:"containerized"`
	NamespaceInfo    map[string]string `json:"namespace_info,omitempty"`
	CollectionTime   time.Time         `json:"collection_time"`
	CollectorVersion string            `json:"collector_version"`
}
