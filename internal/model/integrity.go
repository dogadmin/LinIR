package model

// IntegrityResult captures the holistic anti-rootkit / visibility anomaly
// assessment of the target host. This is not per-file integrity, but rather
// a cross-source consistency check.
type IntegrityResult struct {
	RootkitSuspected    bool     `json:"rootkit_suspected"`
	VisibilityAnomalies []string `json:"visibility_anomalies"`
	ProcessViewMismatch []string `json:"process_view_mismatch"`
	NetworkViewMismatch []string `json:"network_view_mismatch"`
	FileViewMismatch    []string `json:"file_view_mismatch"`
	ModuleViewMismatch  []string `json:"module_view_mismatch"`
	KernelTaint         string   `json:"kernel_taint"`
	RecommendedAction   []string `json:"recommended_action"`
}
