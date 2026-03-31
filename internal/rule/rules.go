package rule

// Rule defines a single scoring rule.
type Rule struct {
	Name        string
	Domain      string // "process"|"network"|"persistence"|"integrity"|"yara"
	Description string
	Score       int
	Severity    string // "low"|"medium"|"high"|"critical"
}

// DefaultRules returns the built-in scoring rules.
// These follow the weighted model from the design spec.
func DefaultRules() []Rule {
	return []Rule{
		{Name: "interpreter_network", Domain: "process", Description: "Interpreter process has active network connection", Score: 20, Severity: "medium"},
		{Name: "exe_in_tmp", Domain: "process", Description: "Process executable in /tmp, /var/tmp, or /dev/shm", Score: 25, Severity: "high"},
		{Name: "exe_deleted", Domain: "process", Description: "Process executable deleted from disk", Score: 20, Severity: "medium"},
		{Name: "suspicious_parent", Domain: "process", Description: "Suspicious parent-child process relationship", Score: 15, Severity: "medium"},
		{Name: "persistence_exists", Domain: "persistence", Description: "Non-standard persistence mechanism found", Score: 25, Severity: "high"},
		{Name: "persistence_target_missing", Domain: "persistence", Description: "Persistence target file does not exist", Score: 15, Severity: "medium"},
		{Name: "persistence_in_tmp", Domain: "persistence", Description: "Persistence target in temporary directory", Score: 25, Severity: "high"},
		{Name: "yara_hit", Domain: "yara", Description: "YARA rule matched", Score: 30, Severity: "high"},
		{Name: "loader_injection", Domain: "integrity", Description: "Dynamic library preload/injection risk", Score: 30, Severity: "high"},
		{Name: "visibility_anomaly", Domain: "integrity", Description: "Cross-source visibility anomaly detected", Score: 25, Severity: "high"},
		{Name: "host_trust_low", Domain: "integrity", Description: "Host environment trust level is low", Score: 20, Severity: "medium"},
		{Name: "rootkit_suspected", Domain: "integrity", Description: "Rootkit indicators detected", Score: 30, Severity: "critical"},
		{Name: "orphan_connection", Domain: "network", Description: "Network connection with no owning process", Score: 20, Severity: "medium"},
		{Name: "raw_socket", Domain: "network", Description: "Raw socket detected", Score: 15, Severity: "medium"},
	}
}
