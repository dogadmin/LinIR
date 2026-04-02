package model

// Capabilities 描述当前平台/权限/环境下的采集能力状态。
// 用于区分"真实无异常"和"采集能力受限导致看不到"。
type Capabilities struct {
	ProcessCollection string `json:"process_collection"` // "full"|"partial"|"unavailable"
	NetworkCollection string `json:"network_collection"` // "full"|"partial"|"unavailable"
	PIDAttribution    string `json:"pid_attribution"`    // "full"|"partial"|"weak"
	PersistenceCollection string `json:"persistence_collection"` // "full"|"partial"|"unavailable"
	WatchModeLayer    string `json:"watch_mode_layer,omitempty"` // "layer1"|"layer2"|"layer3"|""
	RunningPrivileged bool   `json:"running_privileged"`
	Platform          string `json:"platform"` // "linux"|"darwin"|"other"
	RetainedCollection    string   `json:"retained_collection,omitempty"`    // "full"|"partial"|"unavailable"
	TriggerableCollection string   `json:"triggerable_collection,omitempty"` // "full"|"partial"|"unavailable"
	Notes             []string `json:"notes,omitempty"` // 能力受限原因
}
