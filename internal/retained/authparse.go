package retained

import (
	"regexp"
	"strings"
	"time"
)

// MaxAuthEvents caps the number of auth/log events collected to prevent
// memory exhaustion on busy servers.
const MaxAuthEvents = 50000

// ParseSyslogTime parses syslog timestamp format "Jan  2 15:04:05" with year inference.
func ParseSyslogTime(s string, year int) time.Time {
	s = strings.Join(strings.Fields(s), " ")
	t, err := time.Parse("Jan 2 15:04:05", s)
	if err != nil {
		return time.Time{}
	}
	t = t.AddDate(year, 0, 0)
	if t.After(time.Now()) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

// Shared compiled regex patterns for auth log parsing.
// Shared compiled regex patterns for auth log parsing.
var (
	ReSSHAccept = regexp.MustCompile(`(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)\s+port`)
	ReSSHFail   = regexp.MustCompile(`(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port`)
	ReSudo      = regexp.MustCompile(`(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo(?:\[\d+\])?:\s+(\S+)\s+:.*COMMAND=(.*)`)
)

// IsInterestingLogProcess checks if a process name or message is security-relevant.
func IsInterestingLogProcess(process string, message string, extraProcesses []string) bool {
	baseProcesses := []string{
		"sshd", "sudo", "su", "cron", "systemd", "kernel",
		"login", "passwd", "useradd", "userdel",
	}
	for _, p := range baseProcesses {
		if process == p {
			return true
		}
	}
	for _, p := range extraProcesses {
		if process == p {
			return true
		}
	}
	lowerMsg := strings.ToLower(message)
	for _, kw := range []string{
		"authentication failure", "failed password", "accepted",
		"session opened", "session closed", "error", "denied",
		"segfault", "oom-killer", "kernel panic",
	} {
		if strings.Contains(lowerMsg, kw) {
			return true
		}
	}
	return false
}

// ClassifyLogSeverity returns a severity level based on message content.
func ClassifyLogSeverity(message string) string {
	lowerMsg := strings.ToLower(message)
	if strings.Contains(lowerMsg, "error") || strings.Contains(lowerMsg, "fail") ||
		strings.Contains(lowerMsg, "denied") || strings.Contains(lowerMsg, "panic") {
		return "error"
	}
	if strings.Contains(lowerMsg, "warning") || strings.Contains(lowerMsg, "warn") {
		return "warning"
	}
	return "info"
}
