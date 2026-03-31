package model

// SelfCheckResult records the integrity verification of the LinIR binary itself
// and detects environment pollution that could compromise collection reliability.
type SelfCheckResult struct {
	StaticLinkPreferred  bool     `json:"static_link_preferred"`
	SelfPath             string   `json:"self_path"`
	SelfEnvAnomaly       []string `json:"self_env_anomaly"`
	LDPreloadPresent     bool     `json:"ld_preload_present"`
	DYLDInjectionPresent bool     `json:"dyld_injection_present"`
	CollectionConfidence string   `json:"collection_confidence"` // "high"|"medium"|"low"
}
