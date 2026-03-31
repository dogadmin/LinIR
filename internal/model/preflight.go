package model

// PreflightResult captures pre-collection environment validation and
// host trust assessment.
type PreflightResult struct {
	HostTrustLevel      string   `json:"host_trust_level"` // "high"|"medium"|"low"
	PathAnomaly         []string `json:"path_anomaly"`
	EnvAnomaly          []string `json:"env_anomaly"`
	ShellProfileAnomaly []string `json:"shell_profile_anomaly"`
	LoaderAnomaly       []string `json:"loader_anomaly"`
	VisibilityRisk      []string `json:"visibility_risk"`
	Notes               []string `json:"notes"`
}
